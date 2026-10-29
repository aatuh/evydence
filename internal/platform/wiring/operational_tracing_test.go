package wiring

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/telemetry/metrics"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/platform/telemetry"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

func TestOperationalTelemetryKeepsPrivateMetricsAndBalancesActivityWhenDisabled(t *testing.T) {
	registry, err := BuildOperationalMetrics(API, nil)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := BuildOperationalTelemetry(t.Context(), API, config.RuntimeSettings{}, registry)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(t.Context())
	ctx := telemetry.WithObserver(t.Context(), owner)
	child, finishTrace := telemetry.BeginTrace(ctx, telemetry.TraceHTTP)
	if child != ctx {
		t.Fatal("disabled trace wiring changed the caller context")
	}
	finish := telemetry.Start(child, telemetry.OperationObjectWrite)
	body, err := owner.Snapshot(t.Context())
	if err != nil || !strings.Contains(body, `evydence_active_operations{operation="object_write",service="api"} 1`) {
		t.Fatal("trace composition lost existing activity measurements", err)
	}
	finish(telemetry.OutcomeSucceeded, 0)
	finishTrace(telemetry.OutcomeSucceeded)
	body, err = registry.Snapshot(t.Context())
	if err != nil || !strings.Contains(body, `evydence_active_operations{operation="object_write",service="api"} 0`) || !strings.Contains(body, `evydence_operations_total{operation="object_write",outcome="succeeded",service="api"} 1`) {
		t.Fatal("trace composition replaced the original private metrics registry", err)
	}
	var missing *metrics.Registry
	if owner, err := BuildOperationalTelemetry(t.Context(), API, config.RuntimeSettings{}, missing); owner != nil || err == nil {
		t.Fatal("trace composition accepted missing metrics")
	}
}

type traceCleanupFixture struct {
	calls int
	panic bool
	valid bool
}

func (*traceCleanupFixture) Observe(context.Context, telemetry.Event) {}
func (*traceCleanupFixture) BeginTrace(ctx context.Context, _ telemetry.TraceKind) (context.Context, func(telemetry.Outcome)) {
	return ctx, func(telemetry.Outcome) {}
}
func (f *traceCleanupFixture) Shutdown(ctx context.Context) error {
	f.calls++
	deadline, ok := ctx.Deadline()
	f.valid = ok && ctx.Err() == nil && time.Until(deadline) <= time.Second
	if f.panic {
		panic("PRIVATE_EXPORTER_FAILURE")
	}
	return errors.New("PRIVATE_EXPORTER_FAILURE")
}

func TestOperationalTraceCleanupIsSeparateBoundedAndSafeAfterCancellation(t *testing.T) {
	for _, panicClose := range []bool{false, true} {
		var output bytes.Buffer
		logger, err := logging.New(&output, "api", runtimeinfo.Current(), logging.Config{})
		if err != nil {
			t.Fatal(err)
		}
		registry, err := BuildOperationalMetrics(API, nil)
		if err != nil {
			t.Fatal(err)
		}
		owner, err := BuildOperationalTelemetry(t.Context(), API, config.RuntimeSettings{ShutdownCleanupTimeout: time.Minute}, registry)
		if err != nil {
			t.Fatal(err)
		}
		fixture := &traceCleanupFixture{panic: panicClose}
		owner.tracing = fixture
		root, cancel := context.WithCancel(logging.WithLogger(t.Context(), logger))
		cancel()
		owner.Close(root)
		owner.Close(root)
		if fixture.calls != 1 || !fixture.valid || strings.Contains(output.String(), "PRIVATE") || !strings.Contains(output.String(), `"result_code":"uncertain"`) {
			t.Fatal("diagnostic cleanup lost its own bound or disclosed a provider failure")
		}
	}
}
