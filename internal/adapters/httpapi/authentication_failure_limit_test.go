package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthenticationFailuresHaveIndependentDefaultBudget(t *testing.T) {
	s, valid := testServer(t)
	// Exercise production ingress defaults independently of general edge-rate
	// configuration and the test fixture's unrelated service dependencies.
	var err error
	s.ingress, err = newIngressControl(ServerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s.ingress.failureClock = func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }
	request := func(path, credential, remote, forwarded string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = remote
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("X-Forwarded-For", forwarded)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), credential) {
			t.Fatal("authentication failure exposed supplied credential")
		}
		return w
	}
	for i := range 20 {
		w := request("/v1/products", fmt.Sprintf("evy_invalid_failure_fixture_%d", i), "198.51.100.22:1234", fmt.Sprintf("203.0.113.%d", i+1))
		if w.Code != http.StatusUnauthorized {
			t.Fatal("failure below default budget changed contract", i, w.Code)
		}
	}
	if w := request("/v1/products", "evy_invalid_failure_fixture_blocked", "198.51.100.22:4321", "203.0.113.250"); w.Code != http.StatusTooManyRequests {
		t.Fatal("repeated authentication failures remained unbounded", w.Code)
	}
	if w := request("/v1/products", valid, "198.51.100.22:4321", "203.0.113.251"); w.Code != http.StatusTooManyRequests {
		t.Fatal("changing credential selected a fresh failure budget", w.Code)
	}
	if w := request("/v1/products", valid, "198.51.100.23:4321", "203.0.113.251"); w.Code != http.StatusOK {
		t.Fatal("one client's failures blocked an independent client", w.Code)
	}
	if w := request("/v1/version", valid, "198.51.100.22:4321", "203.0.113.251"); w.Code != http.StatusOK {
		t.Fatal("authentication budget blocked public system metadata", w.Code)
	}
}

func TestPublicSSOAndPortalFailuresAreBoundedBeforeCommands(t *testing.T) {
	for _, path := range []string{
		"/v1/sso/session-exchanges", "/v1/sso/authentication-requests", "/v1/sso/saml-authentication-requests",
		"/v1/customer-portal/package", "/v1/customer-portal/package/download", "/v1/customer-portal/package/view", "/v1/customer-portal/package/view/download",
	} {
		t.Run(path, func(t *testing.T) {
			base, _ := testServer(t)
			exchange, portal := &exchangeTransportStub{}, &portalTokenHTTPFake{}
			oidc, saml := &oidcRequestTransportStub{}, &samlRequestTransportStub{}
			s, err := derivedServerFixtureWithContext(t.Context(), base, ServerOptions{AuthenticationFailuresPerMinute: 1, SSOExchangeCommands: exchange, PortalTokenCommands: portal, OIDCAuthenticationRequestCommands: oidc, SAMLAuthenticationRequestCommands: saml})
			if err != nil {
				t.Fatal(err)
			}
			s.ingress.failureClock = func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }
			post := func(body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				if strings.Contains(path, "/view") {
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				r.RemoteAddr = "198.51.100.44:1234"
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				return w
			}
			if w := post("{"); w.Code != http.StatusBadRequest {
				t.Fatal("malformed initial request", w.Code)
			}
			body := `{"provider_id":"provider"}`
			if path == "/v1/sso/session-exchanges" {
				body = `{"provider_id":"provider","subject":"subject","id_token":"private-proof"}`
			}
			if strings.HasPrefix(path, "/v1/customer-portal/") {
				body = `{"token":"private-portal-token"}`
			}
			if strings.Contains(path, "/view") {
				body = "token=private-portal-token"
			}
			w := post(body)
			if w.Code != http.StatusTooManyRequests || exchange.calls+portal.calls+oidc.calls+saml.calls != 0 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Retry-After") == "" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("limited request reached effects or lost safe response", w.Code, exchange.calls, portal.calls)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("client-specific failure limit response can be cached")
			}
			for _, secret := range []string{"private-proof", "private-portal-token", "198.51.100.44", "subject"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("limited response exposed caller information")
				}
			}
		})
	}
}

func TestAuthenticationFailureRecoveryKeepsSuccessfulTrafficAndOtherClientsIndependent(t *testing.T) {
	s, valid := testServer(t)
	i, err := newIngressControl(ServerOptions{AuthenticationFailuresPerMinute: 2, RateLimitBucketCapacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	s.ingress = i
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	i.failureClock = func() time.Time { return now }
	request := func(secret, peer string) int {
		r := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		r.RemoteAddr = peer + ":1234"
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	for range 30 {
		if got := request(valid, "198.51.100.1"); got != 200 {
			t.Fatal("successful traffic exhausted failure capacity", got)
		}
	}
	if got := request("bad-one", "198.51.100.1"); got != 401 {
		t.Fatal(got)
	}
	if got := request(valid, "198.51.100.2"); got != 429 {
		t.Fatal("new client evicted active history", got)
	}
	for range 3 {
		if got := request(valid, "198.51.100.1"); got != 200 {
			t.Fatal("success below failure limit denied", got)
		}
	}
	if got := request("bad-two", "198.51.100.1"); got != 401 {
		t.Fatal(got)
	}
	if got := request(valid, "198.51.100.1"); got != 429 {
		t.Fatal("success reset accumulated failures", got)
	}
	now = now.Add(time.Minute)
	if got := request(valid, "198.51.100.2"); got != 200 {
		t.Fatal("recovery window did not release capacity", got)
	}
	if got := request(valid, "198.51.100.1"); got != 200 {
		t.Fatal("successful recovery retained unused capacity", got)
	}
}

func TestFailureLimiterKeysArePrivatePerProcessAndClass(t *testing.T) {
	one, err := newIngressControl(ServerOptions{RateLimitRequestsPerMinute: 1})
	if err != nil {
		t.Fatal(err)
	}
	two, err := newIngressControl(ServerOptions{RateLimitRequestsPerMinute: 1})
	if err != nil {
		t.Fatal(err)
	}
	peer := "198.51.100.40"
	if one.opaqueLimitKey("credential", peer) == two.opaqueLimitKey("credential", peer) {
		t.Fatal("limiter state is linkable across process keys")
	}
	if one.opaqueLimitKey("credential", peer) == one.opaqueLimitKey("portal", peer) {
		t.Fatal("independent failure classes collide")
	}
	if one.opaqueLimitKey("credential", peer) == one.opaqueLimitKey("credential", "198.51.100.41") {
		t.Fatal("independent client identities collide")
	}
	s, _ := testServer(t)
	s.ingress = one
	r := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	r.RemoteAddr = peer + ":1234"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if len(one.edgeLimiter.buckets) != 1 {
		t.Fatal("edge state not exercised")
	}
	for key := range one.edgeLimiter.buckets {
		if len(key) != 64 || strings.Contains(key, peer) {
			t.Fatal("raw or unbounded identity retained in edge limiter")
		}
	}
}
