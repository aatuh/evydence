package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestNativeEndpointSyntaxPreservesSupportedForms(t *testing.T) {
	for _, tc := range []struct{ name, raw, endpoint string }{
		{"AWS_ENDPOINT_URL_KMS", "https://kms.private.test/prefix", "https://kms.private.test/prefix"},
		{"AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.2/credentials?mode=a", "http://169.254.170.2/credentials?mode=a"},
		{"AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://[fd00:ec2::23]/credentials", "http://[fd00:ec2::23]/credentials"},
		{"AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://[::ffff:127.0.0.1]/credentials", "http://[::ffff:127.0.0.1]/credentials"},
		{"AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://localhost:8080/base", "http://localhost:8080/base"},
		{"AZURE_AUTHORITY_HOST", "https://login.private.test", "https://login.private.test"},
		{"MSI_ENDPOINT", "http://127.0.0.1:8080/token?mode=a", "http://127.0.0.1:8080/token?mode=a"},
		{"HTTP_PROXY", "proxy.private.test:3128", "http://proxy.private.test:3128"},
		{"HTTPS_PROXY", "socks5h://user:PRIVATE_PASSWORD@[::1]:1080", "socks5h://user:PRIVATE_PASSWORD@[::1]:1080"},
		{"GCE_METADATA_HOST", "[::1]:8080", "http://[::1]:8080"},
		{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/id?mode=a", "/v2/credentials/id?mode=a"},
	} {
		value, err := parseNativeValue(nativeDefinitionByName(t, tc.name), tc.raw)
		if err != nil || value.raw != tc.raw || value.endpoint.String() != tc.endpoint {
			t.Fatal("native endpoint grammar or raw input changed", tc.name, err)
		}
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
			t.Fatal("parsed native endpoint exposed supplied credentials", err)
		}
	}
}

func TestNativeListSyntaxPreservesNativeSemantics(t *testing.T) {
	path := strings.Join([]string{"/bin", "", "/PRIVATE directory"}, string(os.PathListSeparator))
	for _, tc := range []struct {
		name, raw string
		items     []string
		ports     []uint16
	}{
		{"PGHOST", "db.private.test,::1,/PRIVATE SOCKET", []string{"db.private.test", "::1", "/PRIVATE SOCKET"}, nil},
		{"PGHOST", "db,,other", []string{"db", "", "other"}, nil},
		{"PGPORT", "5432,5433", nil, []uint16{5432, 5433}},
		{"PGPORT", "005432,5433", nil, []uint16{5432, 5433}},
		{"PATH", path, []string{"/bin", "", "/PRIVATE directory"}, nil},
		{"SSL_CERT_DIR", strings.Join([]string{"/PRIVATE/one", "/PRIVATE/two"}, string(os.PathListSeparator)), []string{"/PRIVATE/one", "/PRIVATE/two"}, nil},
		{"NO_PROXY", "localhost, .EXAMPLE.com,10.0.0.0/8,[::1]:443", []string{"localhost", ".example.com", "10.0.0.0/8", "[::1]:443"}, nil},
		{"NO_PROXY", ",*,", []string{"*"}, nil},
		{"AWS_AUTH_SCHEME_PREFERENCE", "sigv4, sigv4a", []string{"sigv4", "sigv4a"}, nil},
		{"AWS_AUTH_SCHEME_PREFERENCE", "sigv4,, sigv4a,", []string{"sigv4", "sigv4a"}, nil},
		{"AZURE_ADDITIONALLY_ALLOWED_TENANTS", "tenant-a;*", []string{"tenant-a", "*"}, nil},
	} {
		value, err := parseNativeValue(nativeDefinitionByName(t, tc.name), tc.raw)
		if err != nil || value.raw != tc.raw || !slices.Equal(value.items, tc.items) || !slices.Equal(value.ports, tc.ports) {
			t.Fatal("native list grammar or typed items changed", tc.name, err)
		}
	}
}

func TestNativeSyntaxRejectsMalformedAndUnboundedInputsSafely(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"AWS_ENDPOINT_URL_KMS", "http://kms.private.test"},
		{"AWS_ENDPOINT_URL_KMS", "https://PRIVATE_USER:PRIVATE_PASSWORD@kms.test"},
		{"AWS_ENDPOINT_URL_KMS", "https://kms.test?PRIVATE_QUERY=value"},
		{"AWS_ENDPOINT_URL_KMS", "https://kms.test#PRIVATE_FRAGMENT"},
		{"AWS_ENDPOINT_URL_KMS", "https://::1"},
		{"AWS_ENDPOINT_URL_KMS", "https://[not-ip]"},
		{"AWS_ENDPOINT_URL_KMS", "https://kms.test:65536"},
		{"AWS_ENDPOINT_URL_KMS", "https://kms.test:"},
		{"AWS_ENDPOINT_URL_KMS", "https://[fe80::1%25eth0]"},
		{"AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://203.0.113.1/credentials"},
		{"AWS_CONTAINER_CREDENTIALS_FULL_URI", "file:///PRIVATE/credentials"},
		{"HTTP_PROXY", "http://PRIVATE_PROXY:bad"},
		{"HTTP_PROXY", "ftp://PRIVATE_PROXY:3128"},
		{"HTTP_PROXY", "http://PRIVATE_PROXY:3128/ignored-path"},
		{"HTTP_PROXY", "http://PRIVATE_PROXY:3128?ignored=query"},
		{"GCE_METADATA_HOST", "http://PRIVATE_METADATA:8080"},
		{"GCE_METADATA_HOST", "PRIVATE_METADATA:8080/path"},
		{"GCE_METADATA_HOST", "PRIVATE_METADATA:"},
		{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "//PRIVATE_HOST/credentials"},
		{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "http://PRIVATE_HOST/credentials"},
		{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/credentials#PRIVATE_FRAGMENT"},
		{"PGHOST", strings.Repeat("host,", 16) + "host"},
		{"PGHOST", "PRIVATE BAD HOST"},
		{"PGPORT", "0"},
		{"PGPORT", "65536"},
		{"PGPORT", "5432,"},
		{"PGPORT", strings.Repeat("5432,", 16) + "5432"},
		{"SSL_CERT_DIR", "/PRIVATE\nDIRECTORY"},
		{"SSL_CERT_DIR", "/" + strings.Repeat("x", 4096)},
		{"SSL_CERT_DIR", strings.Repeat("/dir"+string(os.PathListSeparator), 256) + "/dir"},
		{"NO_PROXY", "http://PRIVATE_HOST"},
		{"NO_PROXY", "PRIVATE_HOST:65536"},
		{"NO_PROXY", "10.0.0.0/99"},
		{"NO_PROXY", "bad*PRIVATE_HOST"},
		{"NO_PROXY", "*PRIVATE_HOST"},
		{"NO_PROXY", strings.Repeat("host,", 256) + "host"},
		{"AZURE_ADDITIONALLY_ALLOWED_TENANTS", "tenant-a;;tenant-b"},
	} {
		value, err := parseNativeValue(nativeDefinitionByName(t, tc.name), tc.raw)
		if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(value, nativeValue{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("invalid native syntax returned partial output or unsafe diagnostics", tc.name, err)
		}
	}
}

func TestNativeSyntaxPoliciesAreOwnedAndIndependentOfOptionNames(t *testing.T) {
	for _, d := range NativeDefinitions() {
		if d.Kind == URL && d.EndpointPolicy == "" {
			t.Fatal("native URL has no declared endpoint policy", d.Name)
		}
		for i := range d.AllowedHTTPPrefixes {
			if !d.AllowedHTTPPrefixes[i].IsValid() {
				t.Fatal("native credential policy contains an invalid network")
			}
			d.AllowedHTTPPrefixes[i] = netip.MustParsePrefix("203.0.113.0/24")
		}
	}
	d := nativeDefinitionByName(t, "AWS_CONTAINER_CREDENTIALS_FULL_URI")
	d.Name = "RENAMED_NATIVE_OPTION"
	if value, err := parseNativeValue(d, "http://203.0.113.1/credentials"); !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(value, nativeValue{}) {
		t.Fatal("caller mutation or rename changed native credential address policy", err)
	}
	d = nativeDefinitionByName(t, "PGPORT")
	d.Name = "RENAMED_NATIVE_OPTION"
	if value, err := parseNativeValue(d, "5432,5433"); err != nil || !slices.Equal(value.ports, []uint16{5432, 5433}) {
		t.Fatal("renaming native list lost its schema grammar", err)
	}
}

func TestNativeSyntaxValidatesShadowedFallbackAndInactiveProvider(t *testing.T) {
	for _, extra := range [][]string{
		{"HTTP_PROXY=http://proxy.test:3128", "http_proxy=http://PRIVATE_PROXY:bad"},
		{"EVYDENCE_SIGNING_KEY_MODE=local", "AWS_ENDPOINT_URL_KMS=PRIVATE_INVALID_URL"},
	} {
		input, err := parseRoleInput(roleEnvironment(t, API, false, extra...), API)
		if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, parsedInput{}) {
			t.Fatal("role evaluator accepted malformed inactive or shadowed native input", err)
		}
	}
}

func TestHTTPBaseEndpointRejectsUnbracketedIPv6(t *testing.T) {
	if endpoint, err := parseHTTPEndpoint("https://::1", TLSBaseEndpoint, false); !errors.Is(err, ErrInvalidValue) || endpoint != nil {
		t.Fatal("base endpoint accepted ambiguous unbracketed IPv6")
	}
}
