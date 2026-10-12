// Package httpclient provides the narrowly scoped outbound HTTP policy used by
// provider adapters. It is deliberately not an application HTTP abstraction.
package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrDestinationDenied is intentionally safe to return to callers: it does
	// not reveal the resolved address, proxy configuration, or provider URL.
	ErrDestinationDenied = errors.New("outbound destination denied")
	ErrResponseTooLarge  = errors.New("outbound response exceeds configured limit")
)

const defaultMaxResponseBytes int64 = 1 << 20

// Resolver is injectable only to make destination-policy tests deterministic.
// Production uses net.DefaultResolver.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Config defines the provider-adapter egress policy. AllowedHosts uses exact
// normalized host names; an empty allowlist permits any non-prohibited HTTPS
// host. HTTP is permitted only for an explicitly enabled loopback development
// endpoint.
type Config struct {
	Timeout                   time.Duration
	MaxResponseBytes          int64
	AllowedHosts              []string
	AllowInsecureForLocalhost bool
	Client                    *http.Client
	Resolver                  Resolver
}

type destinationPolicy struct {
	allowedHosts              map[string]struct{}
	allowInsecureForLocalhost bool
	resolver                  Resolver
}

type policyTransport struct {
	base             http.RoundTripper
	policy           destinationPolicy
	maxResponseBytes int64
}

// New returns a client that disables ambient proxy use, requires TLS 1.2 or
// newer for HTTPS, rejects redirects, pins each connection attempt to a
// freshly validated IP address, and bounds a response body. A supplied client
// is copied so tests can retain their transport without changing the runtime
// policy.
func New(cfg Config) (*http.Client, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	maxResponseBytes := cfg.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = defaultMaxResponseBytes
	}
	allowedHosts, err := normalizeAllowedHosts(cfg.AllowedHosts)
	if err != nil {
		return nil, err
	}
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	policy := destinationPolicy{
		allowedHosts:              allowedHosts,
		allowInsecureForLocalhost: cfg.AllowInsecureForLocalhost,
		resolver:                  resolver,
	}

	client := http.Client{Timeout: timeout}
	if cfg.Client != nil {
		client = *cfg.Client
		client.Timeout = timeout
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	if transport, ok := base.(*http.Transport); ok {
		clone := transport.Clone()
		clone.Proxy = nil
		clone.DialContext = policy.dialContext
		clone.TLSClientConfig = cloneTLSConfig(clone.TLSClientConfig)
		base = clone
	}
	client.Transport = policyTransport{base: base, policy: policy, maxResponseBytes: maxResponseBytes}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return ErrDestinationDenied
	}
	return &client, nil
}

func cloneTLSConfig(in *tls.Config) *tls.Config {
	if in == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	clone := in.Clone()
	if clone.MinVersion < tls.VersionTLS12 {
		clone.MinVersion = tls.VersionTLS12
	}
	return clone
}

func normalizeAllowedHosts(hosts []string) (map[string]struct{}, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	allowed := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		normalized := normalizeHost(host)
		if normalized == "" {
			return nil, ErrDestinationDenied
		}
		allowed[normalized] = struct{}{}
	}
	return allowed, nil
}

func (p destinationPolicy) validateURL(ctx context.Context, endpoint *url.URL) error {
	if endpoint == nil || endpoint.User != nil || endpoint.Host == "" {
		return ErrDestinationDenied
	}
	host := normalizeHost(endpoint.Hostname())
	if host == "" {
		return ErrDestinationDenied
	}
	if len(p.allowedHosts) > 0 {
		if _, ok := p.allowedHosts[host]; !ok {
			return ErrDestinationDenied
		}
	}
	if endpoint.Scheme != "https" && (endpoint.Scheme != "http" || !p.allowInsecureForLocalhost || !isLoopbackHost(host)) {
		return ErrDestinationDenied
	}
	return p.validateHost(ctx, host)
}

func (p destinationPolicy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrDestinationDenied
	}
	host = normalizeHost(host)
	if host == "" || (len(p.allowedHosts) > 0 && !p.hostAllowed(host)) {
		return nil, ErrDestinationDenied
	}
	addresses, err := p.resolveAndValidate(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{}
	var lastErr error
	for _, address := range addresses {
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrDestinationDenied
}

func (p destinationPolicy) validateHost(ctx context.Context, host string) error {
	_, err := p.resolveAndValidate(ctx, host)
	return err
}

func (p destinationPolicy) resolveAndValidate(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if !p.allowedAddress(host, address.Unmap()) {
			return nil, ErrDestinationDenied
		}
		return []netip.Addr{address.Unmap()}, nil
	}
	resolved, err := p.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(resolved) == 0 {
		return nil, ErrDestinationDenied
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	for _, resolvedAddress := range resolved {
		address := resolvedAddress.Unmap()
		if !p.allowedAddress(host, address) {
			return nil, ErrDestinationDenied
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func (p destinationPolicy) allowedAddress(host string, address netip.Addr) bool {
	if p.allowInsecureForLocalhost && isLoopbackHost(host) && address.IsLoopback() {
		return true
	}
	return !prohibitedAddress(address)
}

func (p destinationPolicy) hostAllowed(host string) bool {
	_, ok := p.allowedHosts[host]
	return ok
}

func (p policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, ErrDestinationDenied
	}
	if err := p.policy.validateURL(req.Context(), req.URL); err != nil {
		return nil, err
	}
	response, err := p.base.RoundTrip(req)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	response.Body = &limitedReadCloser{ReadCloser: response.Body, remaining: p.maxResponseBytes}
	return response, nil
}

type limitedReadCloser struct {
	io.ReadCloser
	remaining int64
	exceeded  bool
}

func (r *limitedReadCloser) Read(buffer []byte) (int, error) {
	if r.exceeded {
		return 0, ErrResponseTooLarge
	}
	if r.remaining <= 0 {
		var probe [1]byte
		count, err := r.ReadCloser.Read(probe[:])
		if count > 0 {
			r.exceeded = true
			return 0, ErrResponseTooLarge
		}
		return count, err
	}
	if int64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	count, err := r.ReadCloser.Read(buffer)
	r.remaining -= int64(count)
	return count, err
}

func prohibitedAddress(address netip.Addr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsPrivate() {
		return true
	}
	if address.Is4() {
		for _, prefix := range prohibitedIPv4Prefixes {
			if prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}

var prohibitedIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

func normalizeHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.ContainsAny(host, "/\\@") {
		return ""
	}
	return host
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.Unmap().IsLoopback()
}

func (p destinationPolicy) String() string {
	return fmt.Sprintf("outbound destination policy (%d allowed hosts)", len(p.allowedHosts))
}
