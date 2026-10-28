package oteltrace

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func TestCollectorProtocolBoundsRedirectsAndSanitizedFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   []byte
	}{
		{"redirect", http.StatusTemporaryRedirect, nil},
		{"unavailable", http.StatusServiceUnavailable, []byte("PRIVATE_PROVIDER_FAILURE")},
		{"oversized", http.StatusOK, bytes.Repeat([]byte("x"), 65537)},
		{"malformed protobuf", http.StatusOK, []byte{0x0a, 0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if _, err := io.Copy(io.Discard, io.LimitReader(r.Body, 1024*1024)); err != nil {
					t.Error(err)
					return
				}
				w.Header().Set("Content-Type", "application/x-protobuf")
				w.Header().Set("Location", "/PRIVATE_REDIRECT")
				w.WriteHeader(test.status)
				_, _ = w.Write(test.body)
			}))
			defer server.Close()
			client, err := newHTTPClient(traceTestConfig(server))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Stop(context.WithoutCancel(t.Context())) }()
			err = client.UploadTraces(t.Context(), []*tracepb.ResourceSpans{{}})
			if err != errExport || strings.Contains(err.Error(), "PRIVATE") || calls.Load() != 1 {
				t.Fatal("collector protocol failure escaped its bound, redirect policy or safe error")
			}
		})
	}
}

func TestRootSamplingAndDurableParentDecisionRemainIndependentOfAmbientContext(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1024*1024))
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer server.Close()
	config := traceTestConfig(server)
	config.SamplePerMillion = 0
	adapter, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adapter.Shutdown(context.WithoutCancel(t.Context())) }()
	ctx := telemetry.WithObserver(t.Context(), adapter)
	child, finish := telemetry.BeginTrace(ctx, telemetry.TraceHTTP)
	if carrier := telemetry.TraceContextFromContext(child); !carrier.Valid() || carrier.Sampled() {
		t.Fatal("zero root sampling failed to retain a valid unsampled context")
	}
	finish(telemetry.OutcomeSucceeded)
	for _, sampled := range []bool{false, true} {
		parent, _ := telemetry.NewTraceContext("0123456789abcdef0123456789abcdef", "0123456789abcdef", sampled)
		child, finish := telemetry.BeginTrace(telemetry.WithTraceContext(ctx, parent), telemetry.TraceWorker)
		carrier := telemetry.TraceContextFromContext(child)
		if !carrier.Valid() || carrier.TraceID() != parent.TraceID() || carrier.SpanID() == parent.SpanID() || carrier.Sampled() != sampled {
			t.Fatal("worker root overrode the durable sampling decision or parent trace")
		}
		finish(telemetry.OutcomeSucceeded)
	}
	shutdown, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := adapter.Shutdown(shutdown); err != nil {
		t.Fatal(err)
	}
}
