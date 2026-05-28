package oidcdiscovery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const (
	defaultTimeout       = 10 * time.Second
	maxDiscoveryBodySize = 256 * 1024
	maxJWKSBodySize      = 256 * 1024
)

type Config struct {
	Timeout                   time.Duration
	AllowInsecureForLocalhost bool
	Client                    *http.Client
}

type Client struct {
	httpClient                *http.Client
	allowInsecureForLocalhost bool
}

type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	httpClient := cfg.Client
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Client{httpClient: httpClient, allowInsecureForLocalhost: cfg.AllowInsecureForLocalhost}
}

func (c *Client) FetchOIDCTrustMaterial(ctx context.Context, req app.OIDCDiscoveryRequest) (app.OIDCDiscoveryResult, error) {
	if c == nil || c.httpClient == nil {
		return app.OIDCDiscoveryResult{}, app.ErrValidation
	}
	issuer := strings.TrimRight(strings.TrimSpace(req.Issuer), "/")
	issuerURL, err := parseProviderURL(issuer, c.allowInsecureForLocalhost)
	if err != nil {
		return app.OIDCDiscoveryResult{}, err
	}
	discoveryURL := *issuerURL
	discoveryURL.Path = strings.TrimRight(discoveryURL.Path, "/") + "/.well-known/openid-configuration"
	discoveryURL.RawQuery = ""
	discoveryURL.Fragment = ""

	var doc discoveryDocument
	if err := c.getJSON(ctx, discoveryURL.String(), maxDiscoveryBodySize, &doc); err != nil {
		return app.OIDCDiscoveryResult{}, err
	}
	doc.Issuer = strings.TrimRight(strings.TrimSpace(doc.Issuer), "/")
	doc.JWKSURI = strings.TrimSpace(doc.JWKSURI)
	if doc.Issuer != issuer || doc.JWKSURI == "" {
		return app.OIDCDiscoveryResult{}, app.ErrVerificationFailed
	}
	jwksURL, err := parseProviderURL(doc.JWKSURI, c.allowInsecureForLocalhost)
	if err != nil {
		return app.OIDCDiscoveryResult{}, err
	}
	var jwks map[string]any
	if err := c.getJSON(ctx, jwksURL.String(), maxJWKSBodySize, &jwks); err != nil {
		return app.OIDCDiscoveryResult{}, err
	}
	return app.OIDCDiscoveryResult{
		Issuer: doc.Issuer,
		JWKS:   jwks,
		Checks: []domain.VerifyCheck{
			{Name: "oidc_discovery_document", Result: "passed"},
			{Name: "oidc_jwks_fetch", Result: "passed"},
		},
		Limitations: []string{"OIDC discovery refreshes public JWKS trust material only; it does not authenticate users or synchronize provider groups."},
	}, nil
}

func (c *Client) getJSON(ctx context.Context, endpoint string, maxBytes int64, out any) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return app.ErrValidation
	}
	httpReq.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return errors.New("fetch oidc metadata")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return app.ErrVerificationFailed
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxBytes+1))
	if err := decoder.Decode(out); err != nil {
		return app.ErrVerificationFailed
	}
	if decoder.InputOffset() > maxBytes {
		return app.ErrVerificationFailed
	}
	return nil
}

func parseProviderURL(raw string, allowInsecureLocalhost bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, app.ErrValidation
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if parsed.Scheme == "http" && allowInsecureLocalhost && localhostHost(parsed.Hostname()) {
		return parsed, nil
	}
	return nil, app.ErrValidation
}

func localhostHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
