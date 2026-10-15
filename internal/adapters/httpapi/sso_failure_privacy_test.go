package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type deniedExchangeTransportStub struct{ err error }

func (f deniedExchangeTransportStub) ExchangeSSOCredential(context.Context, identityapp.ExchangeSSOCredentialInput) (identitydomain.ProviderVerification, identitydomain.SSOSession, string, error) {
	return identitydomain.ProviderVerification{ID: "private-assessment"}, identitydomain.SSOSession{ID: "private-session", UserID: "private-account"}, "private-credential", f.err
}

func TestPublicSSOFailureResponseDoesNotDiscloseIdentityState(t *testing.T) {
	var baseline map[string]any
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"unauthorized", identityapp.ErrUnauthorized}, {"missing identity", identityapp.ErrNotFound},
		{"permission denied", identityapp.ErrForbidden}, {"proof rejected", identityapp.ErrVerificationFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ssoExchangeCommands: deniedExchangeTransportStub{tc.err}}
			r := httptest.NewRequest("POST", "/v1/sso/session-exchanges", strings.NewReader(`{"provider_id":"provider","subject":"claimed-subject","id_token":"proof"}`))
			w := httptest.NewRecorder()
			s.exchangeSSOCredential(w, r)
			if w.Code != 401 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("public authentication failure disclosed identity state", w.Code)
			}
			var problem map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem["detail"] != "unauthorized" {
				t.Fatal("public failure did not use generic detail")
			}
			delete(problem, "request_id") // Correlation IDs vary independently for every request.
			if baseline == nil {
				baseline = problem
			} else if !reflect.DeepEqual(baseline, problem) {
				t.Fatal("public failure changed with identity lookup outcome")
			}
			for _, secret := range []string{"private-assessment", "private-session", "private-account", "private-credential", "claimed-subject"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("failed exchange leaked protected output")
				}
			}
		})
	}
}
