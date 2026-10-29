package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type workerEntryTraceFixture struct {
	workerObservationFixture
	parent   telemetry.TraceContext
	child    telemetry.TraceContext
	starts   int
	finishes []telemetry.Outcome
}

func (f *workerEntryTraceFixture) BeginTrace(ctx context.Context, kind telemetry.TraceKind) (context.Context, func(telemetry.Outcome)) {
	if kind != telemetry.TraceWorker {
		panic("unexpected worker trace kind")
	}
	f.starts++
	f.parent = telemetry.TraceContextFromContext(ctx)
	return telemetry.WithTraceContext(ctx, f.child), func(outcome telemetry.Outcome) { f.finishes = append(f.finishes, outcome) }
}

func TestWorkerTraceStartsFromClaimAndOwnsActualProcessingOutcome(t *testing.T) {
	parent, _ := telemetry.NewTraceContext("0123456789abcdef0123456789abcdef", "0123456789abcdef", true)
	child, _ := telemetry.NewTraceContext("0123456789abcdef0123456789abcdef", "fedcba9876543210", true)
	for _, test := range []struct {
		name       string
		processing error
		ack        error
		outcome    telemetry.Outcome
	}{
		{"success", nil, nil, telemetry.OutcomeSucceeded},
		{"processing failure", errors.New("PRIVATE_PROCESSING_FAILURE"), nil, telemetry.OutcomeFailed},
		{"uncertain acknowledgment", nil, errors.New("PRIVATE_DATABASE_FAILURE"), telemetry.OutcomeUncertain},
	} {
		t.Run(test.name, func(t *testing.T) {
			observer := &workerEntryTraceFixture{child: child}
			root := telemetry.WithObserver(t.Context(), observer)
			queue := &lifecycleQueue{complete: func(ctx context.Context) error {
				if telemetry.TraceContextFromContext(ctx) != child {
					t.Error("acknowledgment lost the active worker trace")
				}
				return test.ack
			}}
			processor := lifecycleProcessor(func(ctx context.Context, _ postgres.ClaimedJob) error {
				if telemetry.TraceContextFromContext(ctx) != child {
					t.Error("processor lost the active worker trace")
				}
				return test.processing
			})
			job := postgres.ClaimedJob{ID: "job_trace", TenantID: "tenant_trace", LeaseToken: "lease_trace", TraceContext: parent}
			if err := drainableWorkerJob(root, queue, processor, job, time.Second); err != nil {
				t.Fatal("tracing changed worker acknowledgment semantics", err)
			}
			if observer.starts != 1 || observer.parent != parent || len(observer.finishes) != 1 || observer.finishes[0] != test.outcome || len(observer.events) != 2 || observer.active != 0 {
				t.Fatal("worker trace lost durable parent, actual outcome or existing metrics")
			}
		})
	}
}

func TestWorkerRestoresOnlyClaimedTraceThroughProcessingAndDrain(t *testing.T) {
	previous, _ := telemetry.NewTraceContext("0123456789abcdef0123456789abcdef", "0123456789abcdef", true)
	claimed, _ := telemetry.NewTraceContext("fedcba9876543210fedcba9876543210", "fedcba9876543210", false)
	for _, test := range []struct {
		name    string
		carrier telemetry.TraceContext
		drain   bool
	}{
		{"claimed", claimed, false},
		{"legacy clears previous", telemetry.TraceContext{}, false},
		{"claimed during drain", claimed, true},
		{"legacy during drain", telemetry.TraceContext{}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, cancel := context.WithCancel(telemetry.WithTraceContext(t.Context(), previous))
			defer cancel()
			seen := make(chan telemetry.TraceContext, 2)
			processor := lifecycleProcessor(func(ctx context.Context, _ postgres.ClaimedJob) error {
				seen <- telemetry.TraceContextFromContext(ctx)
				if test.drain {
					cancel()
				}
				return nil
			})
			queue := &lifecycleQueue{complete: func(ctx context.Context) error {
				seen <- telemetry.TraceContextFromContext(ctx)
				return ctx.Err()
			}}
			job := postgres.ClaimedJob{ID: "job_trace", TenantID: "tenant_trace", LeaseToken: "lease_trace", TraceContext: test.carrier}
			if err := drainableWorkerJob(root, queue, processor, job, time.Second); err != nil {
				t.Fatal("trace restoration changed worker result", err)
			}
			if len(seen) != 2 {
				t.Fatal("processing and completion did not both run")
			}
			for range 2 {
				if <-seen != test.carrier {
					t.Fatal("worker used another job's trace or lost claimed context")
				}
			}
			if telemetry.TraceContextFromContext(root) != previous {
				t.Fatal("job trace mutated the worker root")
			}
		})
	}
}
