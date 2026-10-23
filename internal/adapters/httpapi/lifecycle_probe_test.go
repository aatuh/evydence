package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	operationsquery "github.com/aatuh/evydence/internal/operations/query"
	"github.com/aatuh/evydence/internal/platform/health"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

func TestLifecycleHTTPStartupReadinessAndRecovery(t *testing.T) {
	server, err := newLegacyServerFixture(newLegacyLedgerFixture(repositoryFixtureConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	var pending, outage atomic.Bool
	var calls atomic.Int32
	outage.Store(true)
	service, err := operationsquery.NewReadinessWithConfig([]operationsquery.ReadinessCheck{
		{Name: "migrations", FailureDetail: "schema is unavailable", Check: func(context.Context) error {
			calls.Add(1)
			if pending.Load() {
				return errors.New("CANARY_PRIVATE_MIGRATION_PATH")
			}
			return nil
		}},
		{Name: "object_store", FailureDetail: "provider is unavailable", Check: func(context.Context) error {
			calls.Add(1)
			if outage.Load() {
				return errors.New("https://CANARY_PRIVATE_SECRET@provider.internal/private")
			}
			return nil
		}},
	}, health.Config{CacheTTL: time.Second, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	server.readinessQuery = service
	get := func(path string, wantCode int, wantStatus string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer CANARY_FORGED_CREDENTIAL")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != wantCode || dataMap(t, response.Body.String())["status"] != wantStatus {
			t.Fatalf("probe %s status=%d body=%s", path, response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("proxy could cache lifecycle state beyond the bounded process snapshot", path)
		}
		for _, private := range []string{"CANARY", "provider.internal", "schema is unavailable", "provider is unavailable"} {
			if strings.Contains(response.Body.String(), private) {
				t.Fatal("public probe disclosed private input or operator detail", path, private)
			}
		}
		if wantCode == http.StatusServiceUnavailable && response.Header().Get("Retry-After") == "" {
			t.Fatal("unavailable lifecycle probe omitted retry policy", path)
		}
		return response
	}
	startup := get("/v1/startup", http.StatusOK, "ok")
	if len(dataMap(t, startup.Body.String())) != 1 {
		t.Fatal("startup disclosed dependency inventory")
	}
	get("/v1/ready", http.StatusServiceUnavailable, "unavailable")
	get("/v1/health", http.StatusOK, "ok")
	if calls.Load() != 2 {
		t.Fatal("HTTP lifecycle routes did not share one snapshot or liveness probed dependencies", calls.Load())
	}
	outage.Store(false)
	at = at.Add(time.Second + time.Nanosecond)
	get("/v1/ready", http.StatusOK, "ok")
	pending.Store(true)
	at = at.Add(time.Second + time.Nanosecond)
	get("/v1/startup", http.StatusServiceUnavailable, "unavailable")
	get("/v1/ready", http.StatusServiceUnavailable, "unavailable")
	get("/v1/health", http.StatusOK, "ok")
	if calls.Load() != 6 {
		t.Fatal("startup/readiness did not reuse the current schema failure", calls.Load())
	}
}

func TestLifecycleUnavailableProbeLogsMatchRetryPolicyWithoutSecrets(t *testing.T) {
	var output bytes.Buffer
	logger, err := logging.New(&output, "api", runtimeinfo.Current(), logging.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixtureWithOptions(newLegacyLedgerFixture(repositoryFixtureConfig{}), ServerOptions{Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	server.readinessQuery, err = operationsquery.NewReadiness([]operationsquery.ReadinessCheck{{Name: "migrations", Check: func(context.Context) error { return errors.New("CANARY_PRIVATE_MIGRATION_PATH") }}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/startup", "/v1/ready"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer CANARY_FORGED_SECRET")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable || dataMap(t, response.Body.String())["retryable"] != true {
			t.Fatal("unavailable probe lost retry contract", path, response.Code)
		}
	}
	if strings.Contains(output.String(), "CANARY") {
		t.Fatal("lifecycle diagnostics disclosed credentials or dependency error")
	}
	decoder := json.NewDecoder(&output)
	for _, operation := range []string{"startup", "ready"} {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event["msg"] != "http_request" || event["status"] != float64(http.StatusServiceUnavailable) || event["retry_class"] != "transient" || event["result_code"] != "failed" || event["operation_id"] != logging.Reference("operation", operation) {
			t.Fatal("lifecycle observation differs from response retry policy", event)
		}
	}
}

func TestLifecycleProbesRemainAvailableWhenApplicationAdmissionIsSaturated(t *testing.T) {
	server, err := newLegacyServerFixtureWithOptions(newLegacyLedgerFixture(repositoryFixtureConfig{}), ServerOptions{MaxInFlightRequests: 1, RateLimitRequestsPerMinute: 1})
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	server.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/v1/version", nil))
	if first.Code != http.StatusOK {
		t.Fatal("failed to use the ordinary edge quota", first.Code)
	}
	server.ingress.inFlightRequests <- struct{}{}
	defer func() { <-server.ingress.inFlightRequests }()
	for _, path := range []string{"/v1/health", "/v1/startup", "/v1/ready"} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatal("application saturation made a lifecycle probe unavailable", path, response.Code)
		}
	}
	for _, path := range []string{"/v1/version", "/v1/health/extra", "/v1/%68ealth", "/v1%2fhealth"} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusTooManyRequests {
			t.Fatal("noncanonical or unrelated route bypassed application admission", path, response.Code)
		}
	}
}

func TestLifecycleProbeAdmissionIsBoundedWithoutStarvingLiveness(t *testing.T) {
	server, err := newLegacyServerFixture(newLegacyLedgerFixture(repositoryFixtureConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server.readinessQuery, err = operationsquery.NewReadiness([]operationsquery.ReadinessCheck{{Name: "postgres", Check: func(context.Context) error { calls.Add(1); return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	pool := server.ingress.lifecycleProbes
	if cap(pool) == 0 || cap(pool) > 16 {
		t.Fatal("lifecycle probe admission is not bounded", cap(pool))
	}
	for range cap(pool) {
		pool <- struct{}{}
	}
	defer func() {
		for len(pool) > 0 {
			<-pool
		}
	}()
	for _, path := range []string{"/v1/ready", "/v1/startup"} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusServiceUnavailable || dataMap(t, response.Body.String())["status"] != "unavailable" || response.Header().Get("Retry-After") == "" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("saturated probe pool did not fail fast with safe retry status", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if response.Code != http.StatusOK || calls.Load() != 0 || len(pool) != cap(pool) {
		t.Fatal("dependency probe saturation affected liveness or ran extra probes", response.Code, calls.Load())
	}
}
