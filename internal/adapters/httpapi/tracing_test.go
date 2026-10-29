package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type requestTraceFixture struct {
	operationalMetricsFixture
	starts, ends int
	outcome      telemetry.Outcome
	panicEnd     bool
}

func (f *requestTraceFixture) BeginTrace(ctx context.Context, kind telemetry.TraceKind) (context.Context, func(telemetry.Outcome)) {
	if kind != telemetry.TraceHTTP {
		panic("unexpected trace kind")
	}
	f.starts++
	carrier, _ := telemetry.NewTraceContext("0123456789abcdef0123456789abcdef", "0123456789abcdef", true)
	return telemetry.WithTraceContext(ctx, carrier), func(outcome telemetry.Outcome) {
		f.ends++
		f.outcome = outcome
		if f.panicEnd {
			panic("PRIVATE_OBSERVER_FAILURE")
		}
	}
}

func TestHTTPRequestTraceOwnsActualOutcomeAndPreservesMetricsAndPanic(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		panicValue bool
		panicEnd   bool
		outcome    telemetry.Outcome
	}{
		{"success", http.StatusCreated, false, false, telemetry.OutcomeSucceeded},
		{"rejection", http.StatusForbidden, false, false, telemetry.OutcomeRejected},
		{"failure", http.StatusServiceUnavailable, false, false, telemetry.OutcomeFailed},
		{"handler panic", http.StatusOK, true, false, telemetry.OutcomeUncertain},
		{"observer panic", http.StatusOK, false, true, telemetry.OutcomeSucceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			observer := &requestTraceFixture{panicEnd: test.panicEnd}
			server := &Server{mux: http.NewServeMux(), operationalMetrics: observer}
			response := httptest.NewRecorder()
			request := httptest.NewRequest("GET", "/PRIVATE_PATH?token=PRIVATE_TOKEN", nil)
			request.Header.Set("Traceparent", "PRIVATE_HEADER")
			request.Header.Set("Baggage", "identity=PRIVATE_USER")
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				server.observeRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !telemetry.TraceContextFromContext(r.Context()).Valid() {
						t.Error("handler did not receive the owned request trace")
					}
					telemetry.Record(r.Context(), telemetry.Event{Operation: telemetry.OperationProviderSign, Outcome: telemetry.OutcomeSucceeded})
					w.WriteHeader(test.status)
					if test.panicValue {
						panic("PRIVATE_HANDLER_FAILURE")
					}
				})).ServeHTTP(response, request)
			}()
			if response.Code != test.status || (recovered != nil) != test.panicValue || (test.panicValue && recovered != "PRIVATE_HANDLER_FAILURE") {
				t.Fatal("trace observer changed the handler result or panic")
			}
			if observer.starts != 1 || observer.ends != 1 || observer.outcome != test.outcome || len(observer.requests) != 1 || len(observer.events) != 1 {
				t.Fatal("trace finalization lost actual outcomes or existing metrics")
			}
		})
	}
}
