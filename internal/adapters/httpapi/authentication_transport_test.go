package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestAuthenticationTransportRejectsAmbiguousCredentialsBeforeVerification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []string
		cookies []string
	}{
		{"naked token", []string{"header-secret"}, []string{"cookie-secret"}},
		{"wrong scheme", []string{"Basic header-secret"}, []string{"cookie-secret"}},
		{"blank explicit header", []string{""}, []string{"cookie-secret"}},
		{"whitespace explicit header", []string{" "}, []string{"cookie-secret"}},
		{"leading whitespace", []string{" Bearer header-secret"}, nil},
		{"trailing whitespace", []string{"Bearer header-secret "}, nil},
		{"empty bearer", []string{"Bearer "}, []string{"cookie-secret"}},
		{"joined headers", []string{"Bearer one, Bearer two"}, nil},
		{"duplicate headers", []string{"Bearer one", "Bearer two"}, []string{"cookie-secret"}},
		{"token whitespace", []string{"Bearer one two"}, nil},
		{"duplicate cookies", nil, []string{"cookie-secret", "other-cookie"}},
		{"blank cookie", nil, []string{""}},
		{"API key cookie before usage writes", nil, []string{"evy_key-secret"}},
		{"whitespace cookie", nil, []string{" cookie-secret "}},
		{"missing credentials", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &configuredAuthenticator{actor: identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session"}}
			s := &Server{authn: a}
			r := httptest.NewRequest(http.MethodGet, "https://example.test/v1/products", nil)
			for _, header := range tc.headers {
				r.Header.Add("Authorization", header)
			}
			for _, cookie := range tc.cookies {
				r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: cookie})
			}
			w := httptest.NewRecorder()
			actor, ok := s.authenticate(w, r)
			if ok || actor.TenantID != "" || w.Code != http.StatusUnauthorized || a.calls != 0 {
				t.Fatalf("ambiguous credential admitted: ok=%t status=%d calls=%d", ok, w.Code, a.calls)
			}
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") || strings.Contains(w.Body.String(), "secret") {
				t.Fatal("authentication denial leaked credentials or lost Problem Details")
			}
		})
	}
}

func TestAuthenticationTransportKeepsBearerPrecedenceAndSchemeCase(t *testing.T) {
	for _, scheme := range []string{"Bearer", "bearer", "bEaReR"} {
		a := &configuredAuthenticator{actor: identitydomain.Actor{TenantID: "tenant", KeyID: "key"}}
		s := &Server{authn: a}
		r := httptest.NewRequest(http.MethodGet, "https://example.test/v1/products", nil)
		r.Header.Set("Authorization", scheme+" header-secret")
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "evysso_cookie-secret"})
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "other-cookie"})
		w := httptest.NewRecorder()
		actor, ok := s.authenticate(w, r)
		if !ok || actor.KeyID != "key" || a.calls != 1 || a.secret != "header-secret" || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("explicit bearer precedence or scheme handling changed", scheme)
		}
	}
}

func TestAuthenticationTransportGuardsEveryUnsafeCookieMethod(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		for _, origin := range []string{"", "null", "http://example.test", "https://attacker.test", "https://example.test"} {
			a := &configuredAuthenticator{actor: identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session"}}
			s := &Server{authn: a}
			r := httptest.NewRequest(method, "https://example.test/v1/products", nil)
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "evysso_cookie-secret"})
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
			w := httptest.NewRecorder()
			_, ok := s.authenticate(w, r)
			if origin == "https://example.test" {
				if !ok || a.calls != 1 {
					t.Fatal("same-origin human session was rejected", method)
				}
			} else if ok || w.Code != http.StatusForbidden || a.calls != 0 || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("unsafe cookie Origin reached authentication", method, origin)
			}
		}
	}
}

func TestAuthenticationTransportClearsUnauthorizedCookiesOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		actor  identitydomain.Actor
		err    error
		bearer bool
		allow  bool
		clear  bool
	}{
		{name: "human session", actor: identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session"}, allow: true},
		{name: "API key in cookie", actor: identitydomain.Actor{TenantID: "tenant", KeyID: "key"}, clear: true},
		{name: "collector in cookie", actor: identitydomain.Actor{TenantID: "tenant", KeyID: "key", CollectorID: "collector"}, clear: true},
		{name: "revoked or expired cookie", err: identityapp.ErrUnauthorized, clear: true},
		{name: "valid cookie without grants", err: identityapp.ErrForbidden},
		{name: "invalid bearer with incidental cookie", err: identityapp.ErrUnauthorized, bearer: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &configuredAuthenticator{actor: tc.actor, err: tc.err}
			s := &Server{authn: a}
			r := httptest.NewRequest(http.MethodGet, "https://example.test/v1/products", nil)
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "evysso_cookie-secret"})
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer invalid-token")
			}
			w := httptest.NewRecorder()
			_, ok := s.authenticate(w, r)
			if ok != tc.allow || a.calls != 1 {
				t.Fatal("cookie credential type or revocation was not enforced")
			}
			cookies := w.Result().Cookies()
			if (len(cookies) != 0) != tc.clear {
				t.Fatal("cookie cleanup did not match the failed credential source")
			}
			if tc.clear {
				c := cookies[0]
				if len(cookies) != 1 || c.Name != ssoSessionCookieName || c.Value != "" || c.Path != "/v1" || c.Domain != "" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != -1 || !c.Expires.Before(time.Now()) || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("invalid session cookie was not securely expired")
				}
			}
		})
	}
}

func TestAPIKeyCookieCannotReadOrMutateTenantResources(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			s, secret := testServer(t)
			r := httptest.NewRequest(method, "https://example.test/v1/products", strings.NewReader(`{"name":"Cookie bypass","slug":"cookie-bypass"}`))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", "https://example.test")
			r.Header.Set("Idempotency-Key", "cookie-bypass")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), secret) {
				t.Fatal("API key acquired ambient cookie authority", w.Code)
			}
			valid := getRaw(t, s, secret, "/v1/products", http.StatusOK)
			var result struct {
				Data []json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(valid.Body.Bytes(), &result); err != nil || len(result.Data) != 0 {
				t.Fatal("denied cookie request created tenant resources")
			}
		})
	}
}

func TestSSOSessionCookieAttributesAndCredentialResponseCaching(t *testing.T) {
	w := httptest.NewRecorder()
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	setSSOSessionCookie(w, "session-secret", expires)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("session issuance did not set exactly one cookie")
	}
	c := cookies[0]
	if c.Name != ssoSessionCookieName || c.Value != "session-secret" || c.Path != "/v1" || c.Domain != "" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || !c.Expires.Equal(expires) {
		t.Fatal("session cookie lost its browser security boundary")
	}

	base, secret := testServer(t)
	f := &sessionHTTPFake{}
	s, err := derivedServerFixtureWithContext(t.Context(), base, ServerOptions{SSOSessionCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	response := fixtureSessionPost(t, s, secret, "/v1/sso/sessions", "private-session-response", `{"user_id":"user","provider_id":"provider","expires_at":"2026-12-01T00:00:00Z"}`, http.StatusCreated)
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("session secret response permits HTTP cache storage")
	}
}
