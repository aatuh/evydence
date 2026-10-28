package wiring

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/telemetry/oteltrace"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type operationalTracer interface {
	telemetry.Observer
	telemetry.TraceStarter
	Shutdown(context.Context) error
}

// OperationalTelemetry preserves the private metrics registry and adds only
// optional trace recording. It never retains a request or job context.
type OperationalTelemetry struct {
	httpapi.OperationalMetrics
	tracing operationalTracer
	stop    sync.Once
}

// A diagnostic flush has its own one-second budget, independent of storage and
// provider cleanup. Existing deployment grace includes this second and a four-
// second scheduling margin in addition to drain and resource-cleanup budgets.
const operationalTraceShutdownBudget = time.Second

func BuildOperationalTelemetry(ctx context.Context, process Process, settings config.RuntimeSettings, metrics httpapi.OperationalMetrics) (*OperationalTelemetry, error) {
	if ctx == nil || metrics == nil || (process != API && process != Worker) {
		return nil, oteltrace.ErrConfiguration
	}
	value := reflect.ValueOf(metrics)
	switch value.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		if value.IsNil() {
			return nil, oteltrace.ErrConfiguration
		}
	}
	adapter, err := oteltrace.New(ctx, oteltrace.Config{
		Enabled: settings.TracingEnabled, Service: string(process), Endpoint: settings.TracingEndpoint,
		SamplePerMillion: settings.TracingSamplePerMillion, QueueSize: int(settings.TracingQueueSize),
		ExportTimeout: settings.TracingExportTimeout, ShutdownTimeout: operationalTraceShutdownBudget,
	})
	if err != nil {
		return nil, err
	}
	return &OperationalTelemetry{OperationalMetrics: metrics, tracing: adapter}, nil
}

func (o *OperationalTelemetry) Observe(ctx context.Context, event telemetry.Event) {
	o.OperationalMetrics.Observe(ctx, event)
	o.tracing.Observe(ctx, event)
}

func (o *OperationalTelemetry) Begin(operation telemetry.Operation) func() {
	if active, ok := o.OperationalMetrics.(telemetry.ActivityObserver); ok {
		return active.Begin(operation)
	}
	return nil
}

func (o *OperationalTelemetry) BeginTrace(ctx context.Context, kind telemetry.TraceKind) (context.Context, func(telemetry.Outcome)) {
	return o.tracing.BeginTrace(ctx, kind)
}

// Close deliberately has no error result: optional export cannot replace the
// application's exit result or consume its critical storage-cleanup budget.
func (o *OperationalTelemetry) Close(root context.Context) {
	if o == nil || root == nil {
		return
	}
	defer func() { _ = recover() }()
	o.stop.Do(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(root), operationalTraceShutdownBudget)
		defer cancel()
		failed := false
		defer func() {
			if recover() != nil {
				failed = true
			}
			if failed {
				logging.Emit(root, logging.Cleanup, logging.Fields{OperationID: "trace_shutdown", Result: logging.Uncertain})
			}
		}()
		failed = o.tracing.Shutdown(ctx) != nil
	})
}
