package telemetry

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

type entryTraceFixture struct {
	begin func(context.Context, TraceKind) (context.Context, func(Outcome))
}

func (*entryTraceFixture) Observe(context.Context, Event) {}
func (f *entryTraceFixture) BeginTrace(ctx context.Context, kind TraceKind) (context.Context, func(Outcome)) {
	return f.begin(ctx, kind)
}

func TestBeginTraceDisabledPreservesExactContext(t *testing.T) {
	ctx := t.Context()
	child, finish := BeginTrace(ctx, TraceHTTP)
	if child != ctx {
		t.Fatal("absent tracing changed the caller context")
	}
	finish(OutcomeSucceeded)
	finish(OutcomeFailed)
}

func TestBeginTraceRetainsCancellationAndFinishesExactlyOnce(t *testing.T) {
	carrier, _ := NewTraceContext("0123456789abcdef0123456789abcdef", "0123456789abcdef", true)
	var calls atomic.Int32
	fixture := &entryTraceFixture{begin: func(ctx context.Context, kind TraceKind) (context.Context, func(Outcome)) {
		if kind != TraceWorker {
			t.Fatal("entry point lost its fixed trace kind")
		}
		return WithTraceContext(ctx, carrier), func(outcome Outcome) {
			if outcome != OutcomeUnknown {
				t.Error("arbitrary outcome reached the trace adapter")
			}
			calls.Add(1)
		}
	}}
	root, cancel := context.WithCancel(WithObserver(t.Context(), fixture))
	defer cancel()
	child, finish := BeginTrace(root, TraceWorker)
	if child.Done() != root.Done() || TraceContextFromContext(child) != carrier || TraceContextFromContext(root).Valid() {
		t.Fatal("trace entry changed cancellation or mutated its parent")
	}
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() { finish(Outcome("PRIVATE_OUTCOME")) })
	}
	workers.Wait()
	if calls.Load() != 1 {
		t.Fatal("trace entry finalized more than once")
	}
	cancel()
	if child.Err() != context.Canceled {
		t.Fatal("trace entry lost request cancellation")
	}
}

func TestBeginTraceRejectsArbitraryKindsBeforeCallingAdapter(t *testing.T) {
	fixture := &entryTraceFixture{begin: func(context.Context, TraceKind) (context.Context, func(Outcome)) {
		t.Fatal("unbounded trace kind reached the adapter")
		return nil, nil
	}}
	ctx := WithObserver(t.Context(), fixture)
	for _, kind := range []TraceKind{"", "PRIVATE_TENANT_OR_URL"} {
		child, finish := BeginTrace(ctx, kind)
		if child != ctx {
			t.Fatal("unknown trace kind changed application context")
		}
		finish(OutcomeSucceeded)
	}
}

func TestBeginTraceObserverFaultsCannotChangeApplicationResult(t *testing.T) {
	for _, test := range []struct {
		name  string
		begin func(context.Context, TraceKind) (context.Context, func(Outcome))
	}{
		{"begin panic", func(context.Context, TraceKind) (context.Context, func(Outcome)) { panic("PRIVATE_ADAPTER_ERROR") }},
		{"missing context", func(context.Context, TraceKind) (context.Context, func(Outcome)) { return nil, nil }},
		{"missing finalizer", func(ctx context.Context, _ TraceKind) (context.Context, func(Outcome)) { return ctx, nil }},
		{"lost cancellation", func(context.Context, TraceKind) (context.Context, func(Outcome)) {
			return context.Background(), func(Outcome) {}
		}},
		{"finish panic", func(ctx context.Context, _ TraceKind) (context.Context, func(Outcome)) {
			return ctx, func(Outcome) { panic("PRIVATE_EXPORT_ERROR") }
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := WithObserver(t.Context(), &entryTraceFixture{begin: test.begin})
			child, finish := BeginTrace(ctx, TraceHTTP)
			if child != ctx {
				t.Fatal("faulty tracing changed the application context")
			}
			finish(OutcomeSucceeded)
		})
	}
}
