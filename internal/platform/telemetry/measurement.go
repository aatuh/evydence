package telemetry

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ActivityObserver is an optional bounded activity capability. Begin and its
// release callback must be concurrent-safe, nonblocking and perform no I/O.
// Operations are canonical before delivery; there are no arbitrary attributes.
type ActivityObserver interface{ Begin(Operation) func() }

func beginActivity(observer Observer, operation Operation) (release func()) {
	defer func() { _ = recover() }()
	if active, ok := observer.(ActivityObserver); ok {
		return active.Begin(operation)
	}
	return nil
}

func releaseActivity(release func()) {
	if release == nil {
		return
	}
	defer func() { _ = recover() }()
	release()
}

// Start owns one observation until its returned finalizer runs. Concurrent or
// repeated finalizers count once. The caller must finish admitted work; no
// goroutine, background work, export or cancellation policy is introduced.
func Start(ctx context.Context, operation Operation) func(Outcome, uint32) {
	noop := func(Outcome, uint32) {}
	if ctx == nil {
		return noop
	}
	scope, ok := ctx.Value(observerKey{}).(observerScope)
	if !ok || scope.observer == nil {
		return noop
	}
	operation = operation.Canonical()
	started := time.Now()
	release := beginActivity(scope.observer, operation)
	var once sync.Once
	return func(outcome Outcome, attempt uint32) {
		once.Do(func() {
			defer releaseActivity(release)
			Record(ctx, Event{Operation: operation, Outcome: outcome, Duration: time.Since(started), Attempt: attempt})
		})
	}
}

func OutcomeForError(err error) Outcome {
	if err == nil {
		return OutcomeSucceeded
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return OutcomeCanceled
	}
	return OutcomeFailed
}

// Measure preserves the exact context, return value, error and panic. The
// fallback finalizer records uncertainty during a panic and balances activity.
func Measure[T any](ctx context.Context, operation Operation, call func(context.Context) (T, error)) (T, error) {
	finish := Start(ctx, operation)
	defer finish(OutcomeUncertain, 0)
	value, err := call(ctx)
	finish(OutcomeForError(err), 0)
	return value, err
}

func MeasureError(ctx context.Context, operation Operation, call func(context.Context) error) error {
	finish := Start(ctx, operation)
	defer finish(OutcomeUncertain, 0)
	err := call(ctx)
	finish(OutcomeForError(err), 0)
	return err
}
