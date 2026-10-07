package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type sessionRevocationHTTPFake struct {
	guards, runs     int
	self             bool
	id               string
	guardErr, runErr error
}

func (f *sessionRevocationHTTPFake) AuthorizeRevokeSSOSession(_ context.Context, _ identitydomain.Actor, id string) error {
	f.guards++
	f.id = id
	return f.guardErr
}
func (f *sessionRevocationHTTPFake) AuthorizeRevokeCurrentSSOSession(context.Context, identitydomain.Actor) error {
	f.guards++
	f.self = true
	return f.guardErr
}
func (f *sessionRevocationHTTPFake) RevokeSSOSession(_ context.Context, _ identitydomain.Actor, id string) (identitydomain.SSOSession, error) {
	f.runs++
	f.id = id
	return revokedHTTPFixture(), f.runErr
}
func (f *sessionRevocationHTTPFake) RevokeCurrentSSOSession(context.Context, identitydomain.Actor) (identitydomain.SSOSession, error) {
	f.runs++
	f.self = true
	return revokedHTTPFixture(), f.runErr
}
func revokedHTTPFixture() identitydomain.SSOSession {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	return identitydomain.SSOSession{ID: "session", TenantID: "tenant", UserID: "user", ProviderID: "provider", Prefix: "public-prefix", ExpiresAt: now.Add(time.Hour), RevokedAt: &now, SchemaVersion: identitydomain.SSOSessionSchemaVersion, CreatedAt: now}
}

type sessionRevocationHTTPExecutor struct{ commitErr error }

func (e sessionRevocationHTTPExecutor) WithBody(ctx context.Context, _ domain.Actor, _, _, _ string, _ []byte, guard func(context.Context) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if err := guard(ctx); err != nil {
		return 0, nil, err
	}
	status, out, err := run(ctx)
	if err != nil {
		return 0, nil, err
	}
	if e.commitErr != nil {
		return 0, nil, e.commitErr
	}
	return status, out, nil
}
func TestSSOSessionRevocationHTTPFocusedCommandsStrictBodiesAndPostCommitCookies(t *testing.T) {
	base, secret := testServer(t)
	for _, path := range []string{"/v1/sso/sessions/session/revoke", "/v1/sso/logout"} {
		f := &sessionRevocationHTTPFake{}
		if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{SSOSessionRevocationCommands: f}); err == nil {
			t.Fatal("revocation retained Ledger replay")
		}
		request := func(body string, commitErr error, want int) *httptest.ResponseRecorder {
			t.Helper()
			s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{SSOSessionRevocationCommands: f, DurableCommandExecutor: sessionRevocationHTTPExecutor{commitErr: commitErr}})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", path, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+secret)
			r.Header.Set("Idempotency-Key", "fixture")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal("unexpected revocation HTTP status", w.Code, want)
			}
			return w
		}
		for _, body := range []string{"null", "[]", "{", "{} {}", `{"ignored":true}`, `{"a":1,"a":2}`, string([]byte{0xff}), strings.Repeat(" ", 65537) + "{}"} {
			request(body, nil, 400)
		}
		if f.guards+f.runs != 0 {
			t.Fatal("malformed revocation body reached command")
		}
		for _, stage := range []string{"guard", "run", "commit"} {
			f.guardErr, f.runErr = nil, nil
			var commitErr error
			private := errors.New("private session storage")
			switch stage {
			case "guard":
				f.guardErr = private
			case "run":
				f.runErr = private
			case "commit":
				commitErr = private
			}
			w := request("{}", commitErr, 500)
			if w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "private session storage") || strings.Contains(w.Body.String(), `"id":"session"`) {
				t.Fatal("failed revocation exposed metadata or cleared cookie", stage)
			}
		}
		f.guardErr, f.runErr = nil, nil
		w := request("", nil, 200)
		if !strings.Contains(w.Body.String(), `"id":"session"`) {
			t.Fatal("revocation DTO lost")
		}
		if path == "/v1/sso/logout" {
			cookies := w.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != ssoSessionCookieName || cookies[0].Value != "" || cookies[0].MaxAge != -1 || cookies[0].Path != "/v1" || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode || !f.self {
				t.Fatal("successful logout lost secure cookie clearing")
			}
		} else if w.Header().Get("Set-Cookie") != "" || f.id != "session" {
			t.Fatal("admin revocation changed browser cookie")
		}
	}
}
func TestSSOSessionRevocationHTTPCookieMutationsRequireSameHTTPSOrigin(t *testing.T) {
	base, secret := testServer(t)
	for _, path := range []string{"/v1/sso/sessions/session/revoke", "/v1/sso/logout"} {
		f := &sessionRevocationHTTPFake{}
		s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), legacyFixtureLedger(base), ServerOptions{SSOSessionRevocationCommands: f, DurableCommandExecutor: sessionRevocationHTTPExecutor{}})
		if err != nil {
			t.Fatal(err)
		}
		for _, origin := range []string{"", "https://attacker.example", "http://example.com", "null", "https://example.com/path", "https://user@example.com", "https://example.com?x=1", "https://example.com#fragment", "https://example.com#", "https://example.com, https://attacker.example"} {
			r := httptest.NewRequest("POST", "https://example.com"+path, strings.NewReader("{}"))
			r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
			r.Header.Set("Origin", origin)
			r.Header.Set("Idempotency-Key", "cookie")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 403 || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("unsafe cookie mutation was accepted", origin, w.Code)
			}
		}
		if f.guards+f.runs != 0 {
			t.Fatal("cross-origin cookie reached revocation")
		}
		r := httptest.NewRequest("POST", "https://example.com"+path, strings.NewReader("{}"))
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
		r.Header.Add("Origin", "https://example.com")
		r.Header.Add("Origin", "https://attacker.example")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 || f.guards+f.runs != 0 {
			t.Fatal("ambiguous cookie origin was accepted", w.Code)
		}
		r = httptest.NewRequest("POST", "https://example.com"+path, strings.NewReader("{}"))
		r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
		r.Header.Set("Origin", "https://example.com")
		r.Header.Set("Idempotency-Key", "same-origin")
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 || f.runs != 1 {
			t.Fatal("same-origin cookie mutation failed", w.Code)
		}
		// A deliberate bearer credential is not a cookie-authenticated request.
		r = httptest.NewRequest("POST", "https://example.com"+path, strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Origin", "https://attacker.example")
		r.Header.Set("Idempotency-Key", "bearer")
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("bearer request was treated as ambient cookie authority", w.Code)
		}
	}
}
