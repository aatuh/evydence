package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type configuredAuthenticator struct {
	actor  identitydomain.Actor
	err    error
	calls  int
	secret string
}

func (a *configuredAuthenticator) Authenticate(_ context.Context, secret string) (identitydomain.Actor, error) {
	a.calls++
	a.secret = secret
	return a.actor, a.err
}

func TestConfiguredAuthenticatorPrefersBearerOverSessionCookie(t *testing.T) {
	configured := &configuredAuthenticator{actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"product:read"}}}
	server, err := newLegacyServerFixtureWithOptionsContext(t.Context(), newLegacyLedgerFixture(app.Config{}), ServerOptions{Authenticator: configured})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
	request.Header.Set("Authorization", "Bearer bearer-secret")
	request.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "cookie-secret"})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || configured.secret != "bearer-secret" {
		t.Fatal("configured authenticator did not honor bearer precedence")
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/products", nil)
	request.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: "cookie-secret"})
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || configured.secret != "cookie-secret" {
		t.Fatal("configured authenticator did not accept session cookie fallback")
	}
}

func TestServerUsesConfiguredAuthenticatorAndMapsIdentityErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		actor  identitydomain.Actor
		err    error
		status int
	}{
		{name: "authenticated", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"product:read"}}, status: http.StatusOK},
		{name: "unauthorized", err: identityapp.ErrUnauthorized, status: http.StatusUnauthorized},
		{name: "forbidden", err: identityapp.ErrForbidden, status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			configured := &configuredAuthenticator{actor: test.actor, err: test.err}
			server, err := newLegacyServerFixtureWithOptionsContext(t.Context(), newLegacyLedgerFixture(app.Config{}), ServerOptions{Authenticator: configured})
			if err != nil {
				t.Fatal(err)
			}
			getRaw(t, server, "unused-token", "/v1/products", test.status)
			if configured.calls != 1 {
				t.Fatalf("configured authenticator calls=%d", configured.calls)
			}
		})
	}
}
