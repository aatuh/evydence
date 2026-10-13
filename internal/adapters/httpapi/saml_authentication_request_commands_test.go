package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type samlRequestTransportStub struct{ calls int }

func (f *samlRequestTransportStub) BeginSAMLAuthentication(_ context.Context, in identityapp.BeginSAMLAuthenticationInput) (identitydomain.SAMLAuthenticationRequest, string, error) {
	f.calls++
	return identitydomain.SAMLAuthenticationRequest{ID: "samlreq_fixture", TenantID: "configured-tenant", ProviderID: in.ProviderID, Delivery: in.Delivery, Issuer: "https://idp.example.test", Audience: "sp", Recipient: "https://api.example.test/v1/sso/session-exchanges", NameIDFormat: identitydomain.SAMLNameIDUnspecified, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(5 * time.Minute), SchemaVersion: identitydomain.SAMLAuthenticationRequestSchemaVersion, StateHash: "private-state-canary", TrustFingerprint: "private-trust-canary"}, "evylogin_" + strings.Repeat("A", 43), nil
}
func TestSAMLAuthenticationRequestSeparatesBrowserAndAPIStateDelivery(t *testing.T) {
	for _, delivery := range []string{"api", "browser"} {
		f := &samlRequestTransportStub{}
		s := &Server{samlAuthenticationRequestCommands: f}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/saml-authentication-requests", strings.NewReader(`{"provider_id":"provider","delivery":"`+delivery+`"}`))
		r.Header.Set("Origin", "https://api.example.test")
		w := httptest.NewRecorder()
		s.beginSAMLAuthentication(w, r)
		if w.Code != 201 || f.calls != 1 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "private-") || strings.Contains(w.Body.String(), `"nonce"`) || !strings.Contains(w.Body.String(), `"tenant_id":"configured-tenant"`) || !strings.Contains(w.Body.String(), `"recipient":"https://api.example.test/v1/sso/session-exchanges"`) {
			t.Fatal("SAML state delivery lost public bindings or exposed private material", w.Code)
		}
		cookies := w.Result().Cookies()
		if delivery == "browser" {
			if strings.Contains(w.Body.String(), "evylogin_") || len(cookies) != 1 || cookies[0].Name != samlStateCookieName || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].Path != "/" || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].MaxAge < 1 || cookies[0].MaxAge > 300 {
				t.Fatal("SAML browser state escaped the host-bound cookie")
			}
		} else if len(cookies) != 0 || !strings.Contains(w.Body.String(), "evylogin_") {
			t.Fatal("SAML API did not deliver state once in JSON")
		}
	}
}
func TestSAMLAuthenticationRequestRejectsUnsafeOriginAndMalformedJSONBeforeCreation(t *testing.T) {
	for _, origin := range []string{"", "null", "http://api.example.test", "https://foreign.example.test", "https://api.example.test/"} {
		f := &samlRequestTransportStub{}
		s := &Server{samlAuthenticationRequestCommands: f}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/saml-authentication-requests", strings.NewReader(`{"provider_id":"provider","delivery":"browser"}`))
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		s.beginSAMLAuthentication(w, r)
		if w.Code != 403 || f.calls != 0 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("unsafe SAML origin allocated state", origin, w.Code)
		}
	}
	for _, body := range []string{`null`, `[]`, `{`, `{} {}`, `{"provider_id":null}`, `{"provider_id":"p","provider_id":"q"}`, `{"provider_id":"p","extra":true}`, `{"Provider_ID":"p"}`, `{"provider_id":"p","delivery":null}`, `{"provider_id":"p","delivery":"redirect"}`, "{\"provider_id\":\"\xff\"}"} {
		f := &samlRequestTransportStub{}
		s := &Server{samlAuthenticationRequestCommands: f}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/saml-authentication-requests", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.beginSAMLAuthentication(w, r)
		if w.Code != 400 || f.calls != 0 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("malformed SAML JSON reached creation", body, w.Code)
		}
	}
}

type samlExchangeTransportStub struct {
	calls int
	input identityapp.ExchangeSSOCredentialInput
}

func (f *samlExchangeTransportStub) ExchangeSSOCredential(_ context.Context, in identityapp.ExchangeSSOCredentialInput) (identitydomain.ProviderVerification, identitydomain.SSOSession, string, error) {
	f.calls++
	f.input = in
	return identitydomain.ProviderVerification{Result: "passed"}, identitydomain.SSOSession{ID: "session", ExpiresAt: time.Now().Add(time.Minute)}, "evysso_" + strings.Repeat("B", 43), nil
}
func TestSAMLBrowserExchangeUsesOnlyItsStateCookieAndWithholdsJSONSecret(t *testing.T) {
	f := &samlExchangeTransportStub{}
	s := &Server{ssoExchangeCommands: f}
	r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/session-exchanges", strings.NewReader(`{"provider_id":"provider","subject":"subject","saml_assertion":"assertion","authentication_request_id":"samlreq_fixture","delivery":"browser"}`))
	r.Header.Set("Origin", "https://api.example.test")
	r.AddCookie(&http.Cookie{Name: samlStateCookieName, Value: "evylogin_" + strings.Repeat("A", 43)})
	w := httptest.NewRecorder()
	s.exchangeSSOCredential(w, r)
	if w.Code != 201 || f.calls != 1 || f.input.StateSecret != "evylogin_"+strings.Repeat("A", 43) || strings.Contains(w.Body.String(), "evysso_") {
		t.Fatal("SAML cookie binding or secret delivery failed", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatal("SAML browser did not clear state and set session cookie")
	}
	seenState, seenSession := false, false
	for _, c := range cookies {
		if c.Name == samlStateCookieName {
			seenState = c.MaxAge < 0
		}
		if c.Name == ssoSessionCookieName {
			seenSession = c.HttpOnly && c.Secure && c.Path == "/v1"
		}
		if c.Name == oidcStateCookieName {
			t.Fatal("SAML exchange changed OIDC state cookie")
		}
	}
	if !seenState || !seenSession {
		t.Fatal("SAML cookie lifecycle incomplete")
	}
}
func TestSAMLExchangeRejectsMixedDuplicateAndAmbientProtocolStateBeforeVerification(t *testing.T) {
	for _, tc := range []struct{ delivery, credential, cookie, bodyState string }{
		{"browser", `"saml_assertion":"assertion"`, oidcStateCookieName + "=state", ""},
		{"browser", `"id_token":"token"`, samlStateCookieName + "=state", ""},
		{"browser", `"saml_assertion":"assertion"`, samlStateCookieName + "=state; " + samlStateCookieName + "=duplicate", ""},
		{"browser", `"saml_assertion":"assertion"`, samlStateCookieName + "=state; " + oidcStateCookieName + "=other", ""},
		{"api", `"saml_assertion":"assertion"`, samlStateCookieName + "=state", `,"state_secret":"api-state"`},
		{"browser", `"saml_assertion":"assertion"`, samlStateCookieName + "=state", `,"state_secret":""`},
	} {
		f := &samlExchangeTransportStub{}
		s := &Server{ssoExchangeCommands: f}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/session-exchanges", strings.NewReader(`{"provider_id":"provider","subject":"subject","authentication_request_id":"request","delivery":"`+tc.delivery+`",`+tc.credential+tc.bodyState+`}`))
		r.Header.Set("Origin", "https://api.example.test")
		r.Header.Set("Cookie", tc.cookie)
		w := httptest.NewRecorder()
		s.exchangeSSOCredential(w, r)
		if w.Code != 401 || f.calls != 0 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("ambiguous protocol state reached credential verification", w.Code)
		}
	}
}

func TestSSOExchangeRejectsCaseAliasedCredentialFieldsBeforeVerification(t *testing.T) {
	for _, body := range []string{`{"Provider_ID":"provider","subject":"subject","saml_assertion":"assertion"}`, `{"provider_id":"provider","subject":"subject","saml_assertion":"assertion","SAML_ASSERTION":"other"}`, `{"provider_id":"provider","subject":"subject","id_token":"token","delivery":"browser","authentication_request_id":"request","STATE_SECRET":null}`} {
		f := &samlExchangeTransportStub{}
		s := &Server{ssoExchangeCommands: f}
		r := httptest.NewRequest("POST", "https://api.example.test/v1/sso/session-exchanges", strings.NewReader(body))
		r.Header.Set("Origin", "https://api.example.test")
		r.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "evylogin_" + strings.Repeat("A", 43)})
		w := httptest.NewRecorder()
		s.exchangeSSOCredential(w, r)
		if w.Code != 400 || f.calls != 0 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("case-aliased credential fields reached exchange", w.Code)
		}
	}
}

func TestSAMLHTTPContractRequiresCorrelatedProofAndExcludesPrivateFields(t *testing.T) {
	s, _ := testServer(t)
	raw, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	schemas := asStringAnyMap(t, asStringAnyMap(t, doc["components"])["schemas"])
	for _, name := range []string{"SAMLAuthenticationRequest", "SAMLProviderBinding"} {
		properties := asStringAnyMap(t, asStringAnyMap(t, schemas[name])["properties"])
		for _, private := range []string{"state_hash", "trust_fingerprint", "provider", "saml_signing_certificates"} {
			if _, ok := properties[private]; ok {
				t.Fatal("private SAML material entered public schema", name, private)
			}
		}
	}
	exchange := asStringAnyMap(t, schemas["ExchangeSSOCredentialRequest"])
	api, browser := false, false
	for _, rawBranch := range exchange["oneOf"].([]any) {
		branch := asStringAnyMap(t, rawBranch)
		required := map[string]bool{}
		for _, field := range branch["required"].([]any) {
			required[field.(string)] = true
		}
		if !required["saml_assertion"] {
			continue
		}
		props := asStringAnyMap(t, branch["properties"])
		delivery := asStringAnyMap(t, props["delivery"])["enum"].([]any)[0]
		if !required["authentication_request_id"] {
			t.Fatal("SAML schema permits an uncorrelated assertion")
		}
		if delivery == "api" {
			api = required["state_secret"]
		}
		if delivery == "browser" {
			browser = required["delivery"] && !required["state_secret"] && branch["not"] != nil
		}
	}
	if !api || !browser {
		t.Fatal("SAML API/browser state contract incomplete")
	}
}
