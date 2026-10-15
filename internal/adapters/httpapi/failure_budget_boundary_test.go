package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestFailureBudgetCannotBeResetBySwitchingSSOProtocol(t *testing.T) {
	base, _ := testServer(t)
	portal, exchange, saml := &portalTokenHTTPFake{}, &exchangeTransportStub{}, &samlRequestTransportStub{}
	s, err := derivedServerFixtureWithContext(t.Context(), base, ServerOptions{AuthenticationFailuresPerMinute: 1, PortalTokenCommands: portal, SSOExchangeCommands: exchange, SAMLAuthenticationRequestCommands: saml})
	if err != nil {
		t.Fatal(err)
	}
	s.ingress.failureClock = func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }
	post := func(path, body string) int {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if got := post("/v1/sso/authentication-requests", "{"); got != 400 {
		t.Fatal(got)
	}
	if got := post("/v1/sso/saml-authentication-requests", `{"provider_id":"different-provider"}`); got != 429 {
		t.Fatal("protocol selected fresh quota", got)
	}
	if got := post("/v1/sso/session-exchanges", `{"provider_id":"different-provider","subject":"different-subject","id_token":"different-token"}`); got != 429 {
		t.Fatal("credential values selected fresh quota", got)
	}
	if exchange.calls+saml.calls != 0 {
		t.Fatal("limited SSO reached command effects")
	}
	if got := post("/v1/customer-portal/package", `{"token":"independent-portal-token"}`); got != 200 || portal.calls != 1 {
		t.Fatal("SSO failures consumed independent portal allowance", got)
	}
}

func TestFailureBudgetUsesOnlyConfiguredTrustedProxyClientIdentity(t *testing.T) {
	s, _ := testServer(t)
	var err error
	s.ingress, err = newIngressControl(ServerOptions{AuthenticationFailuresPerMinute: 1, TrustedProxyCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	s.ingress.failureClock = func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }
	request := func(peer string, forwarded ...string) int {
		r := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		r.RemoteAddr = peer
		r.Header.Set("Authorization", "Bearer invalid-token")
		for _, value := range forwarded {
			r.Header.Add("X-Forwarded-For", value)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if got := request("10.1.2.3:443", "198.51.100.1"); got != 401 {
		t.Fatal(got)
	}
	if got := request("10.1.2.3:443", "198.51.100.2"); got != 401 {
		t.Fatal("trusted proxy clients shared quota", got)
	}
	if got := request("10.1.2.3:444", "198.51.100.1"); got != 429 {
		t.Fatal("port reset trusted client quota", got)
	}
	if got := request("10.1.2.3:443", "198.51.100.1", "198.51.100.2"); got != 401 {
		t.Fatal("ambiguous forwarding did not fall back to direct peer", got)
	}
	if got := request("10.1.2.3:443", "not-an-address"); got != 429 {
		t.Fatal("malformed forwarding reset peer fallback quota", got)
	}
	if got := request("203.0.113.4:443", "198.51.100.20"); got != 401 {
		t.Fatal(got)
	}
	if got := request("203.0.113.4:444", "198.51.100.21"); got != 429 {
		t.Fatal("untrusted forwarding reset quota", got)
	}
	if got := request("[::ffff:203.0.113.4]:445", "198.51.100.22"); got != 429 {
		t.Fatal("mapped address selected another quota", got)
	}
}

type blockingFailureAuthenticator struct {
	calls   atomic.Int64
	entered chan struct{}
	release chan struct{}
}

func (a *blockingFailureAuthenticator) Authenticate(ctx context.Context, _ string) (domain.Actor, error) {
	a.calls.Add(1)
	a.entered <- struct{}{}
	select {
	case <-a.release:
	case <-ctx.Done():
	}
	return domain.Actor{}, app.ErrUnauthorized
}

func TestFailureBudgetStopsConcurrentAuthenticationBeforeVerifierEffects(t *testing.T) {
	base, _ := testServer(t)
	a := &blockingFailureAuthenticator{entered: make(chan struct{}, 2), release: make(chan struct{})}
	s, err := derivedServerFixtureWithContext(t.Context(), base, ServerOptions{AuthenticationFailuresPerMinute: 1, Authenticator: a})
	if err != nil {
		t.Fatal(err)
	}
	s.ingress.failureClock = func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }
	var release sync.Once
	var workers sync.WaitGroup
	t.Cleanup(func() { release.Do(func() { close(a.release) }); workers.Wait() })
	request := func(done chan *httptest.ResponseRecorder) {
		defer workers.Done()
		r := httptest.NewRequest(http.MethodGet, "/v1/products", nil).WithContext(t.Context())
		r.Header.Set("Authorization", "Bearer fixture-token")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		done <- w
	}
	first, second := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
	workers.Add(1)
	go request(first)
	select {
	case <-a.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first authentication did not start")
	}
	workers.Add(1)
	go request(second)
	select {
	case w := <-second:
		if w.Code != 429 || a.calls.Load() != 1 {
			t.Fatal("pending reservation did not stop verification", w.Code, a.calls.Load())
		}
	case <-a.entered:
		t.Fatal("concurrent request reached protected verifier")
	case <-time.After(5 * time.Second):
		t.Fatal("limited request did not finish")
	}
	release.Do(func() { close(a.release) })
	select {
	case w := <-first:
		if w.Code != 401 {
			t.Fatal("original failure changed contract", w.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("original authentication did not finish")
	}
}
