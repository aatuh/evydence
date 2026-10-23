package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type workerObservationFixture struct {
	mu     sync.Mutex
	events []telemetry.Event
	active int
}

func (f *workerObservationFixture) Begin(telemetry.Operation) func() {
	f.mu.Lock()
	f.active++
	f.mu.Unlock()
	return func() { f.mu.Lock(); f.active--; f.mu.Unlock() }
}
func (f *workerObservationFixture) Observe(_ context.Context, event telemetry.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

func TestWorkerMeasurementsReflectProcessingAndAcknowledgementSeparately(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		processing, ack            error
		ackOperation               telemetry.Operation
		processOutcome, ackOutcome telemetry.Outcome
	}{
		{"success", nil, nil, telemetry.OperationWorkerComplete, telemetry.OutcomeSucceeded, telemetry.OutcomeSucceeded},
		{"failed", errors.New("PRIVATE_PROCESS_ERROR"), nil, telemetry.OperationWorkerFail, telemetry.OutcomeFailed, telemetry.OutcomeSucceeded},
		{"deferred", errVEXDecisionDependenciesPending, nil, telemetry.OperationWorkerDefer, telemetry.OutcomeFailed, telemetry.OutcomeSucceeded},
		{"uncertain-ack", nil, errors.New("PRIVATE_DATABASE_ERROR"), telemetry.OperationWorkerComplete, telemetry.OutcomeSucceeded, telemetry.OutcomeUncertain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observations := &workerObservationFixture{}
			root := telemetry.WithObserver(t.Context(), observations)
			queue := &lifecycleQueue{complete: func(context.Context) error { return tc.ack }}
			processor := lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error { return tc.processing })
			job := postgres.ClaimedJob{ID: "PRIVATE_JOB", TenantID: "PRIVATE_TENANT", SubjectID: "PRIVATE_RESOURCE", LeaseToken: "PRIVATE_LEASE", Kind: "parse_sbom", Attempts: 3}
			if err := drainableWorkerJob(root, queue, processor, job, time.Second); err != nil {
				t.Fatal("measurement changed worker behavior", err)
			}
			found := map[telemetry.Operation]telemetry.Event{}
			for _, event := range observations.events {
				found[event.Operation] = event
				if event.Duration < 0 || event.Attempt != 3 {
					t.Fatal("worker duration/attempt measurement changed", event)
				}
			}
			if len(observations.events) != 2 || found[telemetry.OperationWorkerProcess].Outcome != tc.processOutcome || found[tc.ackOperation].Outcome != tc.ackOutcome || observations.active != 0 {
				t.Fatal("worker phases lost their actual independent outcomes", observations.events)
			}
			encoded, err := json.Marshal(observations.events)
			if err != nil || strings.Contains(string(encoded), "PRIVATE") {
				t.Fatal("worker metrics disclosed job, tenant, lease or error", err)
			}
		})
	}
}

func TestWorkerMeasurementsDoNotCountLateProcessingAsConfirmedSuccess(t *testing.T) {
	observations := &workerObservationFixture{}
	root, cancel := context.WithCancel(telemetry.WithObserver(t.Context(), observations))
	defer cancel()
	release, returned := make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	queue := &lifecycleQueue{}
	processor := lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error {
		cancel()
		defer close(returned)
		<-release
		return nil
	})
	err := drainableWorkerJob(root, queue, processor, postgres.ClaimedJob{ID: "PRIVATE_JOB", Attempts: 2}, 5*time.Millisecond)
	if !errors.Is(err, errWorkerDrainTimeout) || queue.completions.Load() != 0 || queue.failures.Load() != 0 {
		t.Fatal("timed-out phase changed acknowledgment ownership", err)
	}
	finish()
	workerProbeAwait(t, returned)
	if len(observations.events) != 1 || observations.events[0].Operation != telemetry.OperationWorkerProcess || observations.events[0].Outcome != telemetry.OutcomeUncertain || observations.active != 0 {
		t.Fatal("late processing became confirmed success", observations.events)
	}
}

func TestWorkerClaimMeasurementPreservesClaimResultAndPollingStop(t *testing.T) {
	for _, failure := range []error{nil, errors.New("PRIVATE_CLAIM_ERROR")} {
		observations := &workerObservationFixture{}
		root, cancel := context.WithCancel(telemetry.WithObserver(t.Context(), observations))
		queue := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) { cancel(); return nil, failure }}
		if err := runWorkerLoop(root, queue, lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error { return nil }), shutdownLoopConfig()); err != nil {
			t.Fatal(err)
		}
		cancel()
		if len(observations.events) != 1 || observations.events[0].Operation != telemetry.OperationWorkerClaim || observations.events[0].Outcome != telemetry.OutcomeForError(failure) || observations.active != 0 {
			t.Fatal("claim measurement lost its actual return outcome", observations.events)
		}
	}
}
