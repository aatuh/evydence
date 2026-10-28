package telemetry

import (
	"context"
	"sync"
)

// TraceKind identifies code-owned entry points, never request paths or job IDs.
type TraceKind string

const (
	TraceHTTP   TraceKind = "http_request"
	TraceWorker TraceKind = "worker_job"
)

// TraceStarter is an optional observer capability for an owned entry-point
// span. It must preserve cancellation and unrelated context values, perform no
// synchronous I/O and accept parentage only from the internal TraceContext.
// SDK types, headers, baggage and arbitrary attributes do not cross this port.
type TraceStarter interface {
	BeginTrace(context.Context, TraceKind) (context.Context, func(Outcome))
}

// BeginTrace starts optional tracing without changing application results.
// Disabled or faulty observers retain the exact caller context. A valid
// finalizer records one canonical outcome, including under concurrent calls.
// The owner must finalize admitted work; this helper starts no goroutine.
func BeginTrace(ctx context.Context, kind TraceKind) (child context.Context, finish func(Outcome)) {
	noop := func(Outcome) {}
	child, finish = ctx, noop
	if ctx == nil || (kind != TraceHTTP && kind != TraceWorker) {
		return child, finish
	}
	scope, ok := ctx.Value(observerKey{}).(observerScope)
	if !ok || scope.observer == nil {
		return child, finish
	}
	tracer, ok := scope.observer.(TraceStarter)
	if !ok {
		return child, finish
	}
	defer func() {
		if recover() != nil {
			child, finish = ctx, noop
		}
	}()
	traced, end := tracer.BeginTrace(ctx, kind)
	if traced == nil || traced.Done() != ctx.Done() || end == nil {
		finishTrace(end, OutcomeUncertain)
		return child, finish
	}
	var once sync.Once
	return traced, func(outcome Outcome) {
		once.Do(func() { finishTrace(end, outcome.Canonical()) })
	}
}

func finishTrace(end func(Outcome), outcome Outcome) {
	if end == nil {
		return
	}
	defer func() { _ = recover() }()
	end(outcome)
}
