package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type httpObservation struct {
	method, route string
	status        int
	duration      time.Duration
}

type operationalMetricsFixture struct {
	requests  []httpObservation
	events    []telemetry.Event
	reads     int
	err       error
	panicHTTP bool
}

func (f *operationalMetricsFixture) Observe(_ context.Context, event telemetry.Event) {
	f.events = append(f.events, event)
}

func (f *operationalMetricsFixture) ObserveHTTP(method, route string, status int, duration time.Duration) {
	if f.panicHTTP {
		panic("PRIVATE_METRICS_OBSERVER")
	}
	f.requests = append(f.requests, httpObservation{method, route, status, duration})
}

func (f *operationalMetricsFixture) Snapshot(context.Context) (string, error) {
	f.reads++
	return "evydence_operations_total{service=\"api\",operation=\"provider_sign\",outcome=\"succeeded\"} 3\n", f.err
}

func TestOperationalMetricsObserveActualHTTPOutcomesAndPropagateObserver(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		panicHandler bool
	}{
		{"success", http.StatusCreated, false},
		{"failure", http.StatusServiceUnavailable, false},
		{"panic-after-header", http.StatusOK, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observations := &operationalMetricsFixture{}
			s := &Server{mux: http.NewServeMux(), operationalMetrics: observations,
				logOperations: map[string]string{"GET /v1/products/{id}": "getProduct"}}
			s.mux.HandleFunc("GET /v1/products/{id}", func(http.ResponseWriter, *http.Request) {})
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				s.observeRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					telemetry.Record(r.Context(), telemetry.Event{Operation: telemetry.OperationProviderSign, Outcome: telemetry.OutcomeSucceeded})
					w.WriteHeader(tc.status)
					if tc.panicHandler {
						panic("PRIVATE_HANDLER_ERROR")
					}
				})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/products/PRIVATE_TENANT_ID?token=PRIVATE_TOKEN", nil))
			}()
			if (recovered != nil) != tc.panicHandler || len(observations.requests) != 1 || len(observations.events) != 1 {
				t.Fatal("recording changed the handler outcome or failed to propagate", recovered, observations)
			}
			wantStatus := tc.status
			if tc.panicHandler {
				wantStatus = 0 // An interrupted response must not count as success.
			}
			got := observations.requests[0]
			if got.method != "GET" || got.route != "GET /v1/products/{id}" || got.status != wantStatus || got.duration < 0 {
				t.Fatal("HTTP measurement lost its canonical route or actual outcome", got)
			}
		})
	}
}

func TestOperationalMetricsObserverFailureCannotChangeResponse(t *testing.T) {
	s := &Server{mux: http.NewServeMux(), operationalMetrics: &operationalMetricsFixture{panicHTTP: true}}
	response := httptest.NewRecorder()
	s.observeRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(response, httptest.NewRequest("GET", "/PRIVATE_UNKNOWN_PATH", nil))
	if response.Code != http.StatusAccepted {
		t.Fatal("metrics observer changed the request result")
	}
}

func TestOperationalMetricsScrapeRequiresExplicitInstanceAuthority(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "test", UnitOfWork: factory})
	bootstrap := tenantBootstrapNativeFixture{factory, fixtureSessionCredentials("test"), providerVerificationFixtureClock()}
	secrets := make([]string, 3)
	for i, scopes := range [][]string{{"*"}, {"admin"}, {app.ScopeInstanceAdmin}} {
		_, _, secret, err := bootstrap.BootstrapTenant(t.Context(), "Tenant", "operator", scopes)
		if err != nil {
			t.Fatal(err)
		}
		secrets[i] = secret
	}
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	observations := &operationalMetricsFixture{}
	s.operationalMetrics = observations
	// Even a permissive query adapter cannot authorize access to process data.
	s.metricsQuery = &metricsQueryFake{result: map[string]any{"resource_counts": map[string]int{"evidence": 2}}}
	for _, secret := range secrets[:2] {
		body := getRawWithAccept(t, s, secret, "/v1/metrics", "text/plain", http.StatusOK)
		if observations.reads != 0 || strings.Contains(body.Body.String(), "evydence_operations_total") || !strings.Contains(body.Body.String(), "evydence_resource_count") {
			t.Fatal("tenant authority read global metrics or lost tenant metrics")
		}
	}
	getRawWithAccept(t, s, "invalid-PRIVATE_TOKEN", "/v1/metrics", "text/plain", http.StatusUnauthorized)
	if observations.reads != 0 {
		t.Fatal("unauthenticated scrape read process data")
	}
	getJSON(t, s, secrets[2], "/v1/metrics", http.StatusOK)
	if observations.reads != 0 {
		t.Fatal("JSON compatibility path unnecessarily read process data")
	}
	response := getRawWithAccept(t, s, secrets[2], "/v1/metrics", "text/plain", http.StatusOK)
	if observations.reads != 1 || !strings.Contains(response.Body.String(), "evydence_operations_total") || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("instance scrape lost its protected process metrics")
	}
	observations.err = errors.New("PRIVATE_DATABASE_CREDENTIAL")
	response = getRawWithAccept(t, s, secrets[2], "/v1/metrics", "text/plain", http.StatusServiceUnavailable)
	if strings.Contains(response.Body.String(), "PRIVATE") || strings.Contains(response.Body.String(), "evydence_operations_total") {
		t.Fatal("failed process snapshot leaked partial data or private error")
	}
}

func TestOperationalMetricsOptionReachesNativeConstructor(t *testing.T) {
	observations := &operationalMetricsFixture{}
	opts := nativeConstructorOptions()
	opts.OperationalMetrics = observations
	s, err := NewNativeServerWithOptionsContext(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/health", nil))
	if len(observations.requests) != 1 {
		t.Fatal("native server did not install metrics observer")
	}
}

func TestOperationalMetricsNativeConstructorAllowsDisabledButRejectsTypedNil(t *testing.T) {
	opts := nativeConstructorOptions()
	if s, err := NewNativeServerWithOptionsContext(t.Context(), opts); s == nil || err != nil {
		t.Fatal("disabled embedded recorder became mandatory", err)
	}
	var invalid *operationalMetricsFixture
	opts.OperationalMetrics = invalid
	if s, err := NewNativeServerWithOptionsContext(t.Context(), opts); s != nil || err == nil || !strings.Contains(err.Error(), "OperationalMetrics") {
		t.Fatal("typed-nil recorder was accepted as configured", err)
	}
}
