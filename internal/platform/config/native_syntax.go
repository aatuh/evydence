package config

import (
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
)

type NativeSyntax string

const (
	NativePostgresHosts      NativeSyntax = "postgres-hosts"
	NativePostgresPorts      NativeSyntax = "postgres-ports"
	NativePathList           NativeSyntax = "path-list"
	NativeCertDirectories    NativeSyntax = "certificate-directories"
	NativeNoProxy            NativeSyntax = "no-proxy"
	NativeAuthSchemes        NativeSyntax = "auth-schemes"
	NativeTenants            NativeSyntax = "tenants"
	NativeMetadataHost       NativeSyntax = "metadata-host"
	NativeRelativeCredential NativeSyntax = "relative-credential-uri"
	maxNativeListItems                    = 256
)

func parseNativeValue(d NativeDefinition, raw string) (nativeValue, error) {
	value, err := parseNativeScalar(d, raw)
	if err != nil || raw == "" {
		return value, err
	}
	if d.Kind == URL {
		endpoint, err := parseNativeEndpoint(d, raw)
		if err != nil {
			return nativeValue{}, err
		}
		value.endpoint = *endpoint
	}
	if err := parseNativeSyntax(d, &value); err != nil {
		return nativeValue{}, err
	}
	return value, nil
}

func parseNativeEndpoint(d NativeDefinition, raw string) (*url.URL, error) {
	if d.EndpointPolicy == TLSBaseEndpoint {
		return parseHTTPEndpoint(raw, TLSBaseEndpoint, false)
	}
	proxy := d.EndpointPolicy == NativeProxyEndpoint
	if proxy && !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := parseEndpointURL(raw, proxy)
	if err != nil {
		return nil, err
	}
	switch d.EndpointPolicy {
	case NativeProxyEndpoint:
		if (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery {
			return nil, ErrInvalidValue
		}
	case NativeIdentityEndpoint:
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, ErrInvalidValue
		}
		if u.Scheme == "http" && len(d.AllowedHTTPPrefixes) != 0 {
			if address, err := netip.ParseAddr(u.Hostname()); err == nil {
				allowed := false
				for _, prefix := range d.AllowedHTTPPrefixes {
					allowed = allowed || prefix.Contains(address.Unmap())
				}
				if !allowed {
					return nil, ErrInvalidValue
				}
			}
			// Hostnames still require the native SDK's DNS/destination check
			// during explicit resolution. This pure phase never looks them up.
		}
	default:
		return nil, ErrInvalidValue
	}
	return u, nil
}

func parseNativeSyntax(d NativeDefinition, value *nativeValue) error {
	switch d.Syntax {
	case "":
		return nil
	case NativeMetadataHost:
		u, err := parseHTTPEndpoint("http://"+value.raw, APIClientEndpoint, false)
		if err != nil || u.Path != "" {
			return ErrInvalidValue
		}
		value.endpoint = *u
		return nil
	case NativeRelativeCredential:
		u, err := url.Parse(value.raw)
		if err != nil || !strings.HasPrefix(value.raw, "/") || strings.HasPrefix(value.raw, "//") || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" || strings.Contains(value.raw, "#") {
			return ErrInvalidValue
		}
		if _, err := url.ParseQuery(u.RawQuery); err != nil {
			return ErrInvalidValue
		}
		value.endpoint = *u
		return nil
	}
	separator := ","
	switch d.Syntax {
	case NativePathList:
		separator = string(os.PathListSeparator)
	case NativeCertDirectories:
		separator = ":" // Matches Unix x509 roots, independent of PATH syntax.
	case NativeTenants:
		separator = ";"
	}
	if d.MaxItems <= 0 || strings.Count(value.raw, separator)+1 > d.MaxItems {
		return ErrInvalidValue
	}
	parts := strings.Split(value.raw, separator)
	for _, item := range parts {
		if d.MaxItemBytes <= 0 || len(item) > d.MaxItemBytes {
			return ErrInvalidValue
		}
	}
	switch d.Syntax {
	case NativePostgresHosts:
		if err := validateDatabaseSettings(map[string]string{"host": value.raw}); err != nil {
			return err
		}
		value.items = parts
	case NativePostgresPorts:
		for _, item := range parts {
			n, err := strconv.ParseUint(item, 10, 16)
			if err != nil || n == 0 || n > math.MaxUint16 {
				return ErrInvalidValue
			}
			value.ports = append(value.ports, uint16(n))
		}
	case NativePathList, NativeCertDirectories:
		for _, item := range parts {
			if item != "" && strings.TrimSpace(item) == "" {
				return ErrInvalidValue
			}
		}
		value.items = parts // Empty PATH entries retain native current-dir semantics.
	case NativeAuthSchemes, NativeNoProxy:
		for _, item := range parts {
			item = strings.TrimSpace(item)
			if item == "" {
				continue // Both native parsers skip empty entries.
			}
			if d.Syntax == NativeNoProxy {
				item = strings.ToLower(item)
				if !validNativeNoProxy(item) {
					return ErrInvalidValue
				}
			} else if strings.ContainsFunc(item, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
				return ErrInvalidValue
			}
			value.items = append(value.items, item)
		}
	case NativeTenants:
		for _, item := range parts {
			if item == "" || strings.ContainsFunc(item, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
				return ErrInvalidValue
			}
		}
		value.items = parts
	default:
		return ErrInvalidValue
	}
	return nil
}

func validNativeNoProxy(item string) bool {
	if item == "*" {
		return true
	}
	if strings.Contains(item, "/") {
		_, err := netip.ParsePrefix(item)
		return err == nil
	}
	if ip, err := netip.ParseAddr(item); err == nil {
		return ip.Zone() == ""
	}
	host := item
	if strings.Contains(item, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(item)
		if err != nil {
			return false
		}
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return false
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip.Zone() == ""
		}
	}
	if strings.HasPrefix(host, "*.") {
		host = host[2:]
	} else {
		host = strings.TrimPrefix(host, ".")
	}
	if host == "" || strings.Contains(host, "..") {
		return false
	}
	for _, r := range host {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
