package oteltrace

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

type upstreamLogProbeClient struct{ InstanceValue string }

func (*upstreamLogProbeClient) Start(context.Context) error { return nil }
func (*upstreamLogProbeClient) Stop(context.Context) error  { return nil }
func (*upstreamLogProbeClient) UploadTraces(context.Context, []*tracepb.ResourceSpans) error {
	return nil
}

type upstreamLogProbeExporter struct{ InstanceValue string }

func (*upstreamLogProbeExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	return nil
}
func (*upstreamLogProbeExporter) Shutdown(context.Context) error { return nil }

func TestUpstreamTraceDiagnosticsOmitClientAndExporterInstanceFields(t *testing.T) {
	const marker = "diagnostic-instance-field-marker"
	exporter, err := otlptrace.New(t.Context(), &upstreamLogProbeClient{InstanceValue: marker})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
		defer cancel()
		if err := exporter.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	processor := sdktrace.NewBatchSpanProcessor(&upstreamLogProbeExporter{InstanceValue: marker},
		sdktrace.WithMaxQueueSize(16), sdktrace.WithMaxExportBatchSize(16))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
		defer cancel()
		if err := processor.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	for name, value := range map[string]any{"exporter": exporter, "processor": processor} {
		if marshaler, ok := value.(logr.Marshaler); ok {
			value = marshaler.MarshalLog()
		}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), marker) {
			t.Errorf("upstream %s diagnostic includes instance fields", name)
		}
	}
}
