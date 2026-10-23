package telemetry

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type observerFunc func(context.Context, Event)

func (f observerFunc) Observe(ctx context.Context, event Event) { f(ctx, event) }

func TestRecordCanonicalizesUnsafeNamesBeforeDelivery(t *testing.T) {
	const canary = "PRIVATE_tenant_token_url_evidence_CANARY"
	input := Event{
		Operation: Operation(canary), Outcome: Outcome(canary),
		Duration: -time.Second, Attempt: 3,
	}
	var got Event
	ctx := WithObserver(t.Context(), observerFunc(func(_ context.Context, event Event) { got = event }))
	Record(ctx, input)
	if got.Operation != OperationUnknown || got.Outcome != OutcomeUnknown || got.Duration != 0 || got.Attempt != 3 {
		t.Fatalf("unsafe normalized observation: %+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil || strings.Contains(string(encoded), canary) {
		t.Fatal("unsafe value reached the observation sink", err)
	}
	if input.Operation != Operation(canary) || input.Outcome != Outcome(canary) || input.Duration != -time.Second {
		t.Fatal("normalization changed the caller's event")
	}
}

func TestRecordPreservesEventValuesAndCanceledContext(t *testing.T) {
	type contextKey struct{}
	root, cancel := context.WithCancel(context.WithValue(t.Context(), contextKey{}, "inherited"))
	defer cancel()
	want := Event{Operation: OperationProviderSign, Outcome: OutcomeFailed, Duration: 5 * time.Millisecond, Attempt: 2}
	called := false
	ctx := WithObserver(root, observerFunc(func(ctx context.Context, got Event) {
		called = true
		if got != want || ctx.Value(contextKey{}) != "inherited" || ctx.Err() != context.Canceled {
			t.Fatal("observation lost values or the original cancellation", got, ctx.Err())
		}
		got.Operation = OperationUnknown // The sink receives a value copy.
	}))
	cancel()
	Record(ctx, want)
	if !called || want.Operation != OperationProviderSign || root.Err() != context.Canceled {
		t.Fatal("cancellation skipped recording or the sink mutated caller state")
	}
}

func TestRecordMissingDisabledAndPanickingObserversAreSafe(t *testing.T) {
	for _, parent := range []context.Context{nil, t.Context()} {
		Record(parent, Event{})
		child := WithObserver(parent, nil)
		if (parent == nil) != (child == nil) {
			t.Fatal("disabled observer changed whether its parent context exists")
		}
		Record(child, Event{})
	}
	var calls atomic.Int64
	ctx := WithObserver(t.Context(), observerFunc(func(context.Context, Event) { calls.Add(1) }))
	Record(WithObserver(ctx, nil), Event{})
	if calls.Load() != 0 {
		t.Fatal("explicitly disabled observer fell back to its parent")
	}
	Record(ctx, Event{})
	if calls.Load() != 1 {
		t.Fatal("child disablement changed the parent observer")
	}
	for _, observer := range []Observer{
		observerFunc(func(context.Context, Event) { panic("PRIVATE_EXPORTER_ERROR_CANARY") }),
		(*nilObserver)(nil),
	} {
		Record(WithObserver(t.Context(), observer), Event{Operation: OperationSigning, Outcome: OutcomeSucceeded})
	}
	// Reaching a subsequent good observation proves a broken sink cannot prevent
	// the caller from completing or poison another observer.
	Record(ctx, Event{})
	if calls.Load() != 2 {
		t.Fatal("observer failure affected a subsequent application observation")
	}
}

type nilObserver struct{ invoke func() }

func (o *nilObserver) Observe(context.Context, Event) { o.invoke() }

func TestOperationAndOutcomeCatalogsAreFiniteOwnedCopies(t *testing.T) {
	operations, outcomes := Operations(), Outcomes()
	if len(operations) == 0 || len(operations) > 64 || len(outcomes) == 0 || len(outcomes) > 8 {
		t.Fatal("observation vocabulary exceeded its declared cardinality budget")
	}
	seen := map[Operation]bool{}
	for _, op := range operations {
		if op == "" || seen[op] || op.Canonical() != op {
			t.Fatal("invalid operation vocabulary", op)
		}
		seen[op] = true
	}
	seenOutcomes := map[Outcome]bool{}
	for _, outcome := range outcomes {
		if outcome == "" || seenOutcomes[outcome] || outcome.Canonical() != outcome {
			t.Fatal("invalid outcome vocabulary", outcome)
		}
		seenOutcomes[outcome] = true
	}
	operations[0], outcomes[0] = "PRIVATE_MUTATION_CANARY", "PRIVATE_MUTATION_CANARY"
	if Operations()[0] == operations[0] || Outcomes()[0] == outcomes[0] {
		t.Fatal("caller expanded the shared observation vocabulary")
	}
	series := map[Event]bool{}
	ctx := WithObserver(t.Context(), observerFunc(func(_ context.Context, e Event) { series[e] = true }))
	for i := range 10000 {
		value := "PRIVATE_UNBOUNDED_LABEL_" + strconv.Itoa(i)
		Record(ctx, Event{Operation: Operation(value), Outcome: Outcome(value)})
	}
	if len(series) != 1 || !series[Event{Operation: OperationUnknown, Outcome: OutcomeUnknown}] {
		t.Fatal("unrecognized values expanded the recorder's label space")
	}
}

func TestConcurrentObserverContextsRemainIsolated(t *testing.T) {
	var calls atomic.Int64
	var joined sync.WaitGroup
	for i := range 32 {
		want := Event{Operation: OperationWorkerProcess, Outcome: OutcomeSucceeded, Attempt: uint32(i)}
		ctx := WithObserver(t.Context(), observerFunc(func(_ context.Context, got Event) {
			if got != want {
				t.Errorf("another context's event reached this observer: %+v", got)
			}
			calls.Add(1)
		}))
		joined.Go(func() { Record(ctx, want) })
	}
	joined.Wait()
	if calls.Load() != 32 {
		t.Fatal("concurrent contexts lost observations", calls.Load())
	}
}
