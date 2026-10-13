package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestOIDCAuthenticationRequestRouteUsesConfiguredProviderTenantAndBoundsState(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: peripheralFixtureQueryClock})
	owner := seedProviderVerificationFixture(t, ledger, "Owner")
	foreign := seedProviderVerificationFixture(t, ledger, "Foreign")
	trust := ssoProviderFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: providerVerificationFixtureClock()}
	for _, scope := range []ssoProviderFixtureScope{owner, foreign} {
		if _, err := trust.UpdateSSOProviderTrustMaterial(t.Context(), scope.actor, scope.provider.ID, identityapp.UpdateSSOProviderTrustMaterialInput{JWKS: publicSSOFixtureJWKS("login-state")}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	s.bindSSOSessionFixtureResources("fixture-pepper", providerVerificationFixtureClock())
	post := func(id, delivery, origin string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]any{"provider_id": id, "delivery": delivery})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/authentication-requests", bytes.NewReader(body)).WithContext(t.Context())
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []ssoProviderFixtureScope{owner, foreign} {
		w := post(scope.provider.ID, "api", "")
		var response struct {
			Data struct {
				Request oidcAuthenticationRequestMetadata `json:"authentication_request"`
				State   string                            `json:"state_secret"`
				Nonce   string                            `json:"nonce"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 201 || response.Data.Request.TenantID != scope.actor.TenantID || response.Data.State == "" || response.Data.Nonce == "" || len(w.Result().Cookies()) != 0 {
			t.Fatal("public request did not use its configured provider owner", w.Code, err)
		}
		state, err := factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		stored := state.OIDCAuthenticationRequests[response.Data.Request.ID]
		if stored.TenantID != scope.actor.TenantID || stored.ProviderID != scope.provider.ID || len(stored.StateHash) != 64 || len(stored.NonceHash) != 64 || strings.Contains(w.Body.String(), stored.StateHash) || strings.Contains(w.Body.String(), stored.NonceHash) {
			t.Fatal("request owner or private material crossed the public boundary")
		}
	}
	after, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.OIDCAuthenticationRequests) != 2 || len(after.SSOSessions) != len(before.SSOSessions) || len(after.ProviderVerifications) != len(before.ProviderVerifications) || len(after.Idempotency) != len(before.Idempotency) {
		t.Fatal("state creation issued identity/session authority or replay material")
	}
	for _, tc := range []struct {
		id, delivery, origin string
		status               int
	}{
		{"missing", "api", "", 404}, {owner.provider.ID, "browser", "", 403}, {owner.provider.ID, "browser", "https://foreign.example.test", 403}, {owner.provider.ID, " browser ", "https://api.example.test", 400},
	} {
		w := post(tc.id, tc.delivery, tc.origin)
		if w.Code != tc.status || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("unsafe request changed browser state", w.Code)
		}
	}
	unchanged, err := factory.Snapshot()
	if err != nil || len(unchanged.OIDCAuthenticationRequests) != 2 {
		t.Fatal("rejected creation allocated login state", err)
	}
	for range identitydomain.MaximumOIDCAuthenticationRequestsPerProvider - 1 {
		if w := post(owner.provider.ID, "api", ""); w.Code != 201 {
			t.Fatal("provider capacity filled early", w.Code)
		}
	}
	if w := post(owner.provider.ID, "api", ""); w.Code != 429 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "evylogin_") {
		t.Fatal("overflow did not reject without secret delivery", w.Code)
	}
}

type oidcRequestTransportStub struct{ calls int }

func (f *oidcRequestTransportStub) BeginOIDCAuthentication(_ context.Context, in identityapp.BeginOIDCAuthenticationInput) (identitydomain.OIDCAuthenticationRequest, string, string, error) {
	f.calls++
	return identitydomain.OIDCAuthenticationRequest{ID: "request", ProviderID: in.ProviderID, Delivery: in.Delivery, ExpiresAt: time.Now().Add(5 * time.Minute)}, "evylogin_" + strings.Repeat("A", 43), "evynonce_" + strings.Repeat("B", 43), nil
}

func TestOIDCAuthenticationRequestBrowserRequiresSameOriginBeforeCreation(t *testing.T) {
	for _, origin := range []string{"", "null", "https://foreign.example.test", "http://api.example.test", "https://api.example.test/"} {
		f := &oidcRequestTransportStub{}
		s := &Server{oidcAuthenticationRequestCommands: f}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/authentication-requests", strings.NewReader(`{"provider_id":"provider","delivery":"browser"}`))
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		s.beginOIDCAuthentication(w, r)
		if w.Code != http.StatusForbidden || f.calls != 0 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("unsafe browser origin allocated state", origin, w.Code)
		}
	}
}

func TestOIDCAuthenticationRequestSeparatesBrowserAndAPIStateDelivery(t *testing.T) {
	for _, delivery := range []string{"browser", "api"} {
		f := &oidcRequestTransportStub{}
		s := &Server{oidcAuthenticationRequestCommands: f}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/authentication-requests", strings.NewReader(`{"provider_id":"provider","delivery":"`+delivery+`"}`))
		r.Header.Set("Origin", "https://api.example.test")
		w := httptest.NewRecorder()
		s.beginOIDCAuthentication(w, r)
		if w.Code != http.StatusCreated || f.calls != 1 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("request creation failed", w.Code)
		}
		cookies := w.Result().Cookies()
		if delivery == "browser" {
			if strings.Contains(w.Body.String(), "evylogin_") || len(cookies) != 1 || cookies[0].Name != "__Host-evydence_oidc_state" || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" || cookies[0].Domain != "" {
				t.Fatal("browser state was exposed or cookie was not host bound")
			}
		} else if len(cookies) != 0 || !strings.Contains(w.Body.String(), "evylogin_") {
			t.Fatal("API state delivery changed")
		}
	}
}

func TestOIDCLoginContractDeclaresRequiredStateAndModeSpecificDelivery(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	components := asStringAnyMap(t, doc["components"])
	schemas := asStringAnyMap(t, components["schemas"])
	request := asStringAnyMap(t, schemas["ExchangeSSOCredentialRequest"])
	branches, ok := request["oneOf"].([]any)
	if !ok || len(branches) != 3 {
		t.Fatal("contract does not require OIDC state for separate API/browser modes")
	}
	for _, name := range []string{"OIDCAuthenticationRequest", "BeginOIDCAuthenticationResponse"} {
		schema := asStringAnyMap(t, schemas[name])
		props := asStringAnyMap(t, schema["properties"])
		for _, private := range []string{"state_hash", "nonce_hash", "trust_fingerprint"} {
			if _, ok := props[private]; ok {
				t.Fatal("private login material entered the public schema", private)
			}
		}
	}
	response := asStringAnyMap(t, schemas["SSOCredentialExchangeResponse"])
	for _, field := range response["required"].([]any) {
		if field == "secret" {
			t.Fatal("browser delivery falsely promises a JSON secret")
		}
	}
}

func TestOIDCBrowserExchangeRejectsEvenEmptyBodyStateBeforeVerification(t *testing.T) {
	f := &exchangeTransportStub{}
	s := &Server{ssoExchangeCommands: f}
	r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/session-exchanges", strings.NewReader(`{"provider_id":"provider","subject":"subject","id_token":"token","authentication_request_id":"request","delivery":"browser","state_secret":""}`))
	r.Header.Set("Origin", "https://api.example.test")
	r.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "evylogin_" + strings.Repeat("A", 43)})
	w := httptest.NewRecorder()
	s.exchangeSSOCredential(w, r)
	if w.Code != 401 || f.calls != 0 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("browser body state reached verification", w.Code, f.calls)
	}
}

func TestOIDCBrowserExchangeRejectsMalformedDuplicateStateCookies(t *testing.T) {
	for _, suffix := range []string{oidcStateCookieName + `="unterminated`, oidcStateCookieName + `=bad\\value`, oidcStateCookieName} {
		f := &exchangeTransportStub{}
		s := &Server{ssoExchangeCommands: f}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/session-exchanges", strings.NewReader(`{"provider_id":"provider","subject":"subject","id_token":"token","authentication_request_id":"request","delivery":"browser"}`))
		r.Header.Set("Origin", "https://api.example.test")
		r.Header.Set("Cookie", oidcStateCookieName+"=evylogin_"+strings.Repeat("A", 43)+"; "+suffix)
		w := httptest.NewRecorder()
		s.exchangeSSOCredential(w, r)
		if w.Code != 401 || f.calls != 0 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("malformed duplicate selected cookie authority", w.Code, f.calls)
		}
	}
}
