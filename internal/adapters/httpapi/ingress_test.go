package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

func TestServerClientRateLimitHonorsConfiguredTrustedProxies(t *testing.T) {
	ledgerServer, err := NewServerWithOptions(nil, ServerOptions{
		RateLimitRequestsPerMinute: 1,
		TrustedProxyCIDRs:          []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}

	request := func(remote, forwarded string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", forwarded)
		ledgerServer.Handler().ServeHTTP(recorder, req)
		return recorder
	}

	if got := request("10.1.2.3:443", "198.51.100.10").Code; got != http.StatusOK {
		t.Fatalf("trusted proxy first client status=%d", got)
	}
	if got := request("10.1.2.3:443", "198.51.100.11").Code; got != http.StatusOK {
		t.Fatalf("trusted proxy second client status=%d, want independently limited client", got)
	}
	if got := request("10.1.2.3:443", "198.51.100.10").Code; got != http.StatusTooManyRequests {
		t.Fatalf("trusted proxy repeated client status=%d, want rate limited", got)
	}

	untrustedServer, err := NewServerWithOptions(nil, ServerOptions{RateLimitRequestsPerMinute: 1})
	if err != nil {
		t.Fatalf("NewServerWithOptions untrusted: %v", err)
	}
	for _, forwarded := range []string{"198.51.100.20", "198.51.100.21"} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
		req.RemoteAddr = "203.0.113.1:443"
		req.Header.Set("X-Forwarded-For", forwarded)
		untrustedServer.Handler().ServeHTTP(recorder, req)
		if forwarded == "198.51.100.20" && recorder.Code != http.StatusOK {
			t.Fatalf("untrusted proxy first request status=%d", recorder.Code)
		}
		if forwarded == "198.51.100.21" && recorder.Code != http.StatusTooManyRequests {
			t.Fatalf("untrusted proxy changed forwarded address status=%d, want rate limited", recorder.Code)
		}
	}
}

func TestServerRateLimiterBoundsClientBuckets(t *testing.T) {
	server, err := NewServerWithOptions(nil, ServerOptions{
		RateLimitRequestsPerMinute: 10,
		RateLimitBucketCapacity:    2,
	})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	for _, remote := range []string{"198.51.100.1:443", "198.51.100.2:443", "198.51.100.3:443"} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
		req.RemoteAddr = remote
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("request from %s status=%d", remote, recorder.Code)
		}
	}
	if got := server.ingress.edgeLimiter.bucketCount(); got > 2 {
		t.Fatalf("rate-limit buckets=%d, want bounded capacity of 2", got)
	}
}

func TestRequestRateLimiterExpiresWindowState(t *testing.T) {
	limiter := newRequestRateLimiter(1, 2)
	now := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	if !limiter.allow("198.51.100.1", now) {
		t.Fatal("first request was unexpectedly limited")
	}
	if limiter.allow("198.51.100.1", now.Add(30*time.Second)) {
		t.Fatal("second request within the window was not limited")
	}
	if !limiter.allow("198.51.100.1", now.Add(time.Minute)) {
		t.Fatal("request after the expired window remained limited")
	}
}

func TestIngressRejectsOversizedURLsAndUnsupportedBodyEncodings(t *testing.T) {
	server, err := NewServerWithOptions(nil, ServerOptions{MaxURLBytes: 24})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	handler := server.ingressValidationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, testCase := range []struct {
		name string
		path string
		set  func(*http.Request)
	}{
		{name: "oversized URL", path: "/v1/version?query=" + strings.Repeat("a", 32)},
		{name: "compressed body", path: "/v1/version", set: func(req *http.Request) { req.Header.Set("Content-Encoding", "gzip") }},
		{name: "multipart body", path: "/v1/version", set: func(req *http.Request) { req.Header.Set("Content-Type", "multipart/form-data; boundary=test") }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, testCase.path, nil)
			if testCase.set != nil {
				testCase.set(req)
			}
			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"VALIDATION_FAILED"`) {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestIngressLimitsInFlightRequestsAndNativeUploads(t *testing.T) {
	server, err := NewServerWithOptions(nil, ServerOptions{MaxInFlightRequests: 1, MaxConcurrentUploads: 1})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}

	for _, testCase := range []struct {
		name string
		wrap func(http.Handler) http.Handler
		path string
	}{
		{name: "in-flight", wrap: server.inFlightMiddleware, path: "/v1/version"},
		{name: "native upload", wrap: server.uploadConcurrencyMiddleware, path: "/v1/sboms"},
		{name: "build attestation", wrap: server.uploadConcurrencyMiddleware, path: "/v1/builds/build/attestations"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			finished := make(chan struct{})
			handler := testCase.wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				close(entered)
				<-release
				w.WriteHeader(http.StatusNoContent)
			}))
			go func() {
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, testCase.path, nil))
				close(finished)
			}()
			<-entered

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, testCase.path, nil))
			if recorder.Code != http.StatusTooManyRequests || !strings.Contains(recorder.Body.String(), `"code":"RATE_LIMITED"`) {
				t.Fatalf("bounded request status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			close(release)
			<-finished
		})
	}
}

func TestExpensiveTenantRateLimitIsScopedToTenantAndRoute(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	_, _, tenantASecret, err := ledger.BootstrapTenant(t.Context(), "Tenant A", "admin-a", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant A: %v", err)
	}
	_, _, tenantBSecret, err := ledger.BootstrapTenant(t.Context(), "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant B: %v", err)
	}
	server, err := NewServerWithOptions(ledger, ServerOptions{ExpensiveTenantRequestsPerMinute: 1})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	request := func(secret, path, remote string) int {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Content-Type", "application/json")
		server.Handler().ServeHTTP(recorder, req)
		return recorder.Code
	}

	if got := request(tenantASecret, "/v1/vulnerability-scans", "198.51.100.1:443"); got == http.StatusTooManyRequests {
		t.Fatalf("first expensive request for tenant A was unexpectedly limited")
	}
	if got := request(tenantASecret, "/v1/vulnerability-scans", "198.51.100.2:443"); got != http.StatusTooManyRequests {
		t.Fatalf("second expensive request for tenant A status=%d, want 429", got)
	}
	if got := request(tenantBSecret, "/v1/vulnerability-scans", "198.51.100.3:443"); got == http.StatusTooManyRequests {
		t.Fatalf("tenant B inherited tenant A's expensive-route limit")
	}
	if got := request(tenantASecret, "/v1/sboms", "198.51.100.4:443"); got == http.StatusTooManyRequests {
		t.Fatalf("a separate expensive route inherited /v1/vulnerability-scans limit")
	}
}
