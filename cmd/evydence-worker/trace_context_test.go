package main

import (
	"context"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

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
