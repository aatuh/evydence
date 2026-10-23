package httpclient

import (
	"errors"
	"net/url"
	"testing"
)

func TestStaticEndpointUsesDestinationPolicyWithoutResolution(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		local    bool
		allowed  bool
	}{
		{"https://PRIVATE_UNRESOLVABLE.invalid/sign", false, true},
		{"https://8.8.8.8/sign", false, true},
		{"http://8.8.8.8/sign", false, false},
		{"https://user:PRIVATE_PASSWORD@example.invalid/sign", false, false},
		{"https://127.0.0.1/sign", false, false},
		{"https://[::ffff:127.0.0.1]/sign", false, false},
		{"https://localhost/sign", false, false},
		{"http://localhost/sign", true, true},
		{"https://localhost/sign", true, true},
		{"http://127.0.0.1/sign", true, true},
		{"http://[::1]/sign", true, true},
		{"http://example.invalid/sign", true, false},
		{"https://10.0.0.1/sign", true, false},
		{"https://100.64.0.1/sign", false, false},
		{"https://169.254.169.254/sign", false, false},
		{"https://[fe80::1]/sign", false, false},
		{"https://192.0.2.1/sign", false, false},
		{"https://0.0.0.0/sign", false, false},
	} {
		u, err := url.Parse(tc.endpoint)
		if err != nil {
			t.Fatal(err)
		}
		err = ValidateStaticEndpoint(u, tc.local)
		if tc.allowed && err != nil {
			t.Fatal("static validation resolved a name or rejected an allowed destination", err)
		}
		if !tc.allowed && !errors.Is(err, ErrDestinationDenied) {
			t.Fatal("static validation bypassed the existing destination policy", err)
		}
		if err != nil && err.Error() != ErrDestinationDenied.Error() {
			t.Fatal("static validation disclosed input or underlying errors")
		}
	}
	if !errors.Is(ValidateStaticEndpoint(nil, false), ErrDestinationDenied) {
		t.Fatal("nil endpoint was accepted")
	}
}
