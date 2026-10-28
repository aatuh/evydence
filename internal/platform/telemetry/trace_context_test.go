package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestTraceContextAcceptsOnlyCanonicalNonzeroIdentifiers(t *testing.T) {
	traceID := "0123456789abcdef0123456789abcdef"
	spanID := "0123456789abcdef"
	for _, sampled := range []bool{false, true} {
		carrier, ok := NewTraceContext(traceID, spanID, sampled)
		if !ok || !carrier.Valid() || carrier.TraceID() != traceID || carrier.SpanID() != spanID || carrier.Sampled() != sampled {
			t.Fatal("canonical trace context did not round trip")
		}
	}
	for _, test := range []struct{ name, trace, span string }{
		{"empty", "", ""},
		{"zero trace", strings.Repeat("0", 32), spanID},
		{"zero span", traceID, strings.Repeat("0", 16)},
		{"short trace", traceID[1:], spanID},
		{"long span", traceID, spanID + "0"},
		{"uppercase", strings.ToUpper(traceID), spanID},
		{"invalid hex", traceID, "g123456789abcdef"},
		{"whitespace", " " + traceID, spanID},
		{"traceparent header", "00-" + traceID + "-" + spanID + "-01", spanID},
		{"unbounded input", strings.Repeat("a", 65536), spanID},
	} {
		t.Run(test.name, func(t *testing.T) {
			carrier, ok := NewTraceContext(test.trace, test.span, true)
			if ok || carrier.Valid() || carrier != (TraceContext{}) {
				t.Fatal("invalid context retained diagnostic input")
			}
		})
	}
}

func TestTraceContextIsOperationalAndShadowsPreviousJob(t *testing.T) {
	type unrelatedKey struct{}
	root := context.WithValue(context.Background(), unrelatedKey{}, "kept")
	root, cancel := context.WithCancel(root)
	defer cancel()
	carrier, _ := NewTraceContext("0123456789abcdef0123456789abcdef", "0123456789abcdef", true)
	ctx := WithTraceContext(root, carrier)
	if TraceContextFromContext(ctx) != carrier || ctx.Value(unrelatedKey{}) != "kept" || ctx.Done() != root.Done() {
		t.Fatal("trace context changed parent values or cancellation")
	}
	for _, empty := range []context.Context{root, nil} {
		if TraceContextFromContext(empty).Valid() {
			t.Fatal("trace context appeared without an owned carrier")
		}
	}
	// Legacy jobs must not inherit the previous job's trace from a reused root.
	if TraceContextFromContext(WithTraceContext(ctx, TraceContext{})).Valid() {
		t.Fatal("empty job metadata retained another job's trace")
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("trace context lost cancellation")
	}
}

func TestTraceContextDiagnosticRepresentationsOmitIdentifiers(t *testing.T) {
	carrier, _ := NewTraceContext("0123456789abcdef0123456789abcdef", "fedcba9876543210", true)
	encoded, err := json.Marshal(carrier)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{fmt.Sprint(carrier), fmt.Sprintf("%+v", carrier), fmt.Sprintf("%#v", carrier), string(encoded)} {
		if strings.Contains(output, carrier.TraceID()) || strings.Contains(output, carrier.SpanID()) {
			t.Fatal("diagnostic representation disclosed a trace identifier")
		}
	}
}
