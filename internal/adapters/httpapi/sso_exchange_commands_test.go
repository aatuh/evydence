package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type exchangeTransportStub struct{ calls int }

func (f *exchangeTransportStub) ExchangeSSOCredential(context.Context, identityapp.ExchangeSSOCredentialInput) (identitydomain.ProviderVerification, identitydomain.SSOSession, string, error) {
	f.calls++
	return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", identityapp.ErrVerificationFailed
}
func TestSSOExchangeTransportRejectsAmbiguousBodiesBeforeCredentialVerification(t *testing.T) {
	for _, body := range []string{
		`null`, `[]`, `{"provider_id":"p","subject":"s","id_token":null}`,
		`{"provider_id":null,"subject":"s","id_token":"token"}`,
		`{"provider_id":"p","subject":null,"id_token":"token"}`,
		`{"provider_id":"p","subject":"s","id_token":"token","saml_assertion":null}`,
		`{"provider_id":"p","subject":"s","id_token":"token","expires_at":null}`,
		`{"provider_id":"p","provider_id":"q","subject":"s","id_token":"token"}`,
		`{"provider_id":"p","subject":"s","id_token":"token","unknown":true}`,
		`{"provider_id":"p","subject":"s","id_token":"token"} {}`,
		"{\"provider_id\":\"p\",\"subject\":\"s\",\"id_token\":\"\xff\"}",
	} {
		f := &exchangeTransportStub{}
		s, err := newLegacyServerFixtureWithOptions(newLegacyLedgerFixture(app.Config{}), ServerOptions{SSOExchangeCommands: f})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/sso/session-exchanges", strings.NewReader(body)))
		if w.Code != 400 || f.calls != 0 || w.Header().Get("Set-Cookie") != "" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
			t.Fatal("ambiguous body reached exchange or set a cookie", w.Code, f.calls)
		}
	}
}
