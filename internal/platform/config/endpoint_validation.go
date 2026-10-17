package config

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/aatuh/evydence/internal/platform/httpclient"
)

// validateEndpointInput applies code-owned HTTP policies, including inactive
// configured endpoints in the selected role. Database DSNs and S3 authorities
// have different grammars and are validated separately.
func validateEndpointInput(input parsedInput) error {
	for _, d := range Definitions() {
		if d.EndpointPolicy == "" || d.Roles&input.role == 0 {
			continue
		}
		raw := strings.TrimSpace(input.values[d.Name].text)
		if raw == "" {
			continue
		}
		allowLocal := !input.production && d.LocalhostOverride != "" && input.values[d.LocalhostOverride].boolean
		if _, err := parseHTTPEndpoint(raw, d.EndpointPolicy, allowLocal); err != nil {
			return err
		}
	}
	return nil
}

func parseHTTPEndpoint(raw string, policy EndpointPolicy, allowLocal bool) (*url.URL, error) {
	u, err := parseEndpointURL(raw, false)
	if err != nil {
		return nil, err
	}
	switch policy {
	case TLSBaseEndpoint:
		if u.Scheme != "https" || u.RawQuery != "" || u.ForceQuery {
			return nil, ErrInvalidValue
		}
	case APIClientEndpoint:
		if (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.ForceQuery {
			return nil, ErrInvalidValue
		}
	case GatewayEndpoint, GatewayReadinessEndpoint:
		if policy == GatewayReadinessEndpoint && (u.RawQuery != "" || u.ForceQuery) {
			return nil, ErrInvalidValue
		}
		if httpclient.ValidateStaticEndpoint(u, allowLocal) != nil {
			return nil, ErrInvalidValue
		}
	default:
		return nil, ErrInvalidValue
	}
	return u, nil
}

func parseEndpointURL(raw string, allowUserInfo bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" || (!allowUserInfo && u.User != nil) || strings.Contains(raw, "#") {
		return nil, ErrInvalidValue
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "%") || strings.ContainsFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, ErrInvalidValue
	}
	if strings.HasPrefix(u.Host, "[") {
		address, parseErr := netip.ParseAddr(host)
		if parseErr != nil || !address.Is6() {
			return nil, ErrInvalidValue
		}
	} else if strings.Contains(host, ":") {
		return nil, ErrInvalidValue // IPv6 URL authorities require brackets.
	}
	if port := u.Port(); port != "" {
		n, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || n == 0 {
			return nil, ErrInvalidValue
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, ErrInvalidValue
	}
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return nil, ErrInvalidValue
	}
	return u, nil
}
