package oteltrace

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func traceTestConfig(server *httptest.Server) Config {
	return Config{Enabled: true, Service: "api", Endpoint: server.URL + "/v1/traces", SamplePerMillion: 1000000, QueueSize: 16, ExportTimeout: time.Second, ShutdownTimeout: 2 * time.Second, HTTPClient: server.Client()}
}

type traceCountingTransport struct{ calls atomic.Int32 }

func (t *traceCountingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return nil, errors.New("PRIVATE_TRANSPORT_ERROR")
}

func TestDisabledTracingCreatesNoExporterTrafficOrContext(t *testing.T) {
	transport := &traceCountingTransport{}
	adapter, err := New(t.Context(), Config{HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	child, finish := adapter.BeginTrace(ctx, telemetry.TraceHTTP)
	if child != ctx {
		t.Fatal("disabled tracing replaced the caller context")
	}
	finish(telemetry.OutcomeSucceeded)
	adapter.Observe(ctx, telemetry.Event{Operation: telemetry.OperationProviderSign, Outcome: telemetry.OutcomeSucceeded})
	if err := adapter.Shutdown(ctx); err != nil || transport.calls.Load() != 0 {
		t.Fatal("disabled tracing created exporter work", err)
	}
}

func TestOwnedTraceExportUsesInternalParentAndFixedMetadata(t *testing.T) {
	requests := make(chan []byte, 8)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/traces" || r.Header.Get("Content-Type") != "application/x-protobuf" || r.Header.Get("Authorization") != "" || r.Header.Get("Baggage") != "" || r.Header.Get("Traceparent") != "" {
			t.Error("export transport sent unexpected routing, identity or propagation data")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- body
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer server.Close()
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "private.token=PRIVATE_ENVIRONMENT")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=PRIVATE_TOKEN")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://PRIVATE_IGNORED.invalid")
	adapter, err := New(t.Context(), traceTestConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Shutdown(context.WithoutCancel(t.Context())) })
	member, err := baggage.NewMember("private.identity", "PRIVATE_USER")
	if err != nil {
		t.Fatal(err)
	}
	bag, err := baggage.New(member)
	if err != nil {
		t.Fatal(err)
	}
	incoming := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled, Remote: true})
	ctx := trace.ContextWithSpanContext(baggage.ContextWithBaggage(t.Context(), bag), incoming)
	ctx = telemetry.WithObserver(ctx, adapter)
	child, finish := telemetry.BeginTrace(ctx, telemetry.TraceHTTP)
	carrier := telemetry.TraceContextFromContext(child)
	if !carrier.Valid() || carrier.TraceID() == incoming.TraceID().String() || trace.SpanContextFromContext(child).IsValid() || baggage.FromContext(child).Len() != 0 {
		t.Fatal("request root trusted incoming span context or retained baggage")
	}
	failure := errors.New("PRIVATE_PROVIDER_RESPONSE")
	if err := telemetry.MeasureError(child, telemetry.OperationProviderSign, func(callCtx context.Context) error {
		if callCtx != child {
			t.Error("tracing replaced the provider's caller context")
		}
		return failure
	}); err != failure {
		t.Fatal("tracing changed the provider error")
	}
	finish(telemetry.OutcomeSucceeded)
	if err := adapter.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	spans := 0
	for len(requests) > 0 {
		body := <-requests
		if bytes.Contains(body, []byte("PRIVATE")) || bytes.Contains(body, []byte(server.URL)) {
			t.Fatal("trace export disclosed caller, process, environment or collector data")
		}
		var request collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &request); err != nil {
			t.Fatal("collector did not receive standard OTLP protobuf", err)
		}
		for _, resource := range request.ResourceSpans {
			if len(resource.Resource.Attributes) != 1 || resource.Resource.Attributes[0].Key != "service.name" || resource.Resource.Attributes[0].Value.GetStringValue() != "evydence-api" {
				t.Fatal("resource attributes exceeded the fixed service allowlist")
			}
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					spans++
					if len(span.Events) != 0 || len(span.Links) != 0 || span.Status.GetMessage() != "" {
						t.Fatal("span retained unbounded event, link or status prose")
					}
					for _, attr := range span.Attributes {
						if attr.Key != "evydence.operation" && attr.Key != "evydence.outcome" && attr.Key != "evydence.attempt" {
							t.Fatal("span attribute escaped the fixed allowlist")
						}
					}
					switch span.Name {
					case string(telemetry.TraceHTTP):
						if len(span.ParentSpanId) != 0 {
							t.Fatal("HTTP root accepted an incoming parent")
						}
					case string(telemetry.OperationProviderSign):
						parent, parseErr := trace.SpanIDFromHex(carrier.SpanID())
						if parseErr != nil || !bytes.Equal(span.ParentSpanId, parent[:]) {
							t.Fatal("provider span lost its internal request parent")
						}
					default:
						t.Fatal("unbounded span name")
					}
				}
			}
		}
	}
	if spans != 2 {
		t.Fatal("request and provider spans were not both exported", spans)
	}
}

func TestSDKDiagnosticsCannotDiscloseAmbientConfiguration(t *testing.T) {
	var output bytes.Buffer
	otel.SetLogger(funcr.New(func(_, text string) { output.WriteString(text) }, funcr.Options{Verbosity: 127}))
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { output.WriteString(err.Error()) }))
	t.Cleanup(func() { otel.SetLogger(logr.Discard()) })
	t.Setenv("OTEL_TRACES_SAMPLER", "PRIVATE_SAMPLER")
	t.Setenv("OTEL_BSP_MAX_QUEUE_SIZE", "PRIVATE_QUEUE")
	adapter, err := New(t.Context(), Config{Enabled: true, Service: "worker", Endpoint: "https://PRIVATE_COLLECTOR.invalid/v1/traces", SamplePerMillion: 0, QueueSize: 16, ExportTimeout: time.Second, ShutdownTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "PRIVATE") {
		t.Fatal("SDK diagnostics disclosed environment or collector configuration")
	}
}
