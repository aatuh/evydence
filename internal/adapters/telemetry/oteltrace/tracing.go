// Package oteltrace owns optional diagnostic spans and their export lifetime.
// It registers no global tracer provider or propagator.
package oteltrace

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

var (
	ErrConfiguration = errors.New("invalid tracing configuration")
	errExport        = errors.New("trace export unavailable")
)

// Adapter is a private SDK owner. Recording never performs export I/O or stores
// a caller context. Shutdown must run after the application's admitted work.
type Adapter struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
	client   *httpClient
	budget   time.Duration
	closed   atomic.Bool
	stop     sync.Once
	stopErr  error
}

var (
	_ telemetry.Observer     = (*Adapter)(nil)
	_ telemetry.TraceStarter = (*Adapter)(nil)
)

func New(ctx context.Context, cfg Config) (*Adapter, error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	if !cfg.Enabled {
		return &Adapter{}, nil
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, errExport
	}
	client, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	// SDK constructors inspect some OTEL variables before applying options.
	// Disable their global diagnostic channel before any SDK construction, and
	// never pass raw SDK/exporter errors to the application logger. This also
	// enforces the upstream GO-2026-6505 logging workaround for selected versions.
	otel.SetLogger(logr.Discard())
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {}))
	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, errExport
	}
	processor := sdktrace.NewBatchSpanProcessor(exporter,
		sdktrace.WithMaxQueueSize(cfg.QueueSize),
		sdktrace.WithMaxExportBatchSize(min(32, cfg.QueueSize)),
		sdktrace.WithBatchTimeout(time.Second),
		sdktrace.WithExportTimeout(cfg.ExportTimeout),
	)
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", "evydence-"+cfg.Service))),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(float64(cfg.SamplePerMillion)/1000000))),
		sdktrace.WithRawSpanLimits(sdktrace.SpanLimits{AttributeCountLimit: 3, AttributeValueLengthLimit: 64}),
		sdktrace.WithSpanProcessor(processor),
	)
	return &Adapter{provider: provider, tracer: provider.Tracer("evydence/operations"), client: client, budget: cfg.ShutdownTimeout}, nil
}

func cleanContext(ctx context.Context, useParent bool) context.Context {
	clean := baggage.ContextWithoutBaggage(trace.ContextWithSpanContext(ctx, trace.SpanContext{}))
	if !useParent {
		return clean
	}
	parent := telemetry.TraceContextFromContext(ctx)
	if !parent.Valid() {
		return clean
	}
	traceID, traceErr := trace.TraceIDFromHex(parent.TraceID())
	spanID, spanErr := trace.SpanIDFromHex(parent.SpanID())
	if traceErr != nil || spanErr != nil {
		return clean
	}
	var flags trace.TraceFlags
	if parent.Sampled() {
		flags = trace.FlagsSampled
	}
	return trace.ContextWithSpanContext(clean, trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceID, SpanID: spanID, TraceFlags: flags}))
}

func (a *Adapter) BeginTrace(ctx context.Context, kind telemetry.TraceKind) (context.Context, func(telemetry.Outcome)) {
	noop := func(telemetry.Outcome) {}
	if a == nil || a.tracer == nil || a.closed.Load() || ctx == nil || (kind != telemetry.TraceHTTP && kind != telemetry.TraceWorker) {
		return ctx, noop
	}
	spanKind := trace.SpanKindServer
	if kind == telemetry.TraceWorker {
		spanKind = trace.SpanKindConsumer
	}
	parent := cleanContext(ctx, kind == telemetry.TraceWorker)
	_, span := a.tracer.Start(parent, string(kind), trace.WithSpanKind(spanKind),
		trace.WithAttributes(attribute.String("evydence.operation", string(kind))))
	sc := span.SpanContext()
	carrier, _ := telemetry.NewTraceContext(sc.TraceID().String(), sc.SpanID().String(), sc.IsSampled())
	// Return only the neutral carrier, not a mutable SDK span. Other libraries
	// cannot attach arbitrary attributes or events to the owned entry-point span.
	child := baggage.ContextWithoutBaggage(trace.ContextWithSpanContext(ctx, trace.SpanContext{}))
	child = telemetry.WithTraceContext(child, carrier)
	var once sync.Once
	return child, func(outcome telemetry.Outcome) {
		once.Do(func() {
			span.SetAttributes(attribute.String("evydence.outcome", string(outcome.Canonical())))
			span.End()
		})
	}
}

// Observe creates a completed, timestamped child without changing the exact
// context supplied to existing Measure callbacks. Durations are limited to one
// day for trace timestamps; the existing metric retains its own measurement.
func (a *Adapter) Observe(ctx context.Context, event telemetry.Event) {
	if a == nil || a.tracer == nil || a.closed.Load() || ctx == nil {
		return
	}
	end := time.Now()
	duration := max(0, min(event.Duration, 24*time.Hour))
	_, span := a.tracer.Start(cleanContext(ctx, true), string(event.Operation.Canonical()),
		trace.WithTimestamp(end.Add(-duration)),
		trace.WithAttributes(
			attribute.String("evydence.operation", string(event.Operation.Canonical())),
			attribute.String("evydence.outcome", string(event.Outcome.Canonical())),
			attribute.Int64("evydence.attempt", int64(event.Attempt)),
		),
	)
	span.End(trace.WithTimestamp(end))
}

// Shutdown is a bounded best-effort flush followed by cancellation of owned
// network work and SDK shutdown. Its fixed error is diagnostic; daemon wiring
// must not replace application outcomes with export or flush errors.
func (a *Adapter) Shutdown(ctx context.Context) error {
	if a == nil || a.provider == nil {
		return nil
	}
	if ctx == nil {
		return ErrConfiguration
	}
	a.stop.Do(func() {
		a.closed.Store(true)
		cleanup, cancel := context.WithTimeout(ctx, a.budget)
		defer cancel()
		flush, cancelFlush := context.WithTimeout(cleanup, a.budget*3/4)
		flushErr := a.provider.ForceFlush(flush)
		cancelFlush()
		stopErr := a.client.Stop(cleanup)
		providerErr := a.provider.Shutdown(cleanup)
		if flushErr != nil || stopErr != nil || providerErr != nil {
			a.stopErr = errExport
		}
	})
	return a.stopErr
}
