package telemetry

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type measurementObserver struct {
	mu                   sync.Mutex
	events               []Event
	active               int
	operations           []Operation
	panicBegin, panicEnd bool
}

func (o *measurementObserver) Observe(_ context.Context, event Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event)
}
func (o *measurementObserver) Begin(operation Operation) func() {
	if o.panicBegin {
		panic("PRIVATE_OBSERVER_BEGIN")
	}
	o.mu.Lock()
	o.active++
	o.operations = append(o.operations, operation)
	o.mu.Unlock()
	return func() {
		if o.panicEnd {
			panic("PRIVATE_OBSERVER_END")
		}
		o.mu.Lock()
		o.active--
		o.mu.Unlock()
	}
}

func TestMeasurementPreservesContextResultsErrorsAndBalancesActivity(t *testing.T) {
	for _, failure := range []error{nil, errors.New("PRIVATE_PROVIDER_ERROR"), context.Canceled, context.DeadlineExceeded} {
		o := &measurementObserver{}
		ctx := WithObserver(t.Context(), o)
		value := &struct{ private string }{"PRIVATE_PAYLOAD"}
		got, err := Measure(ctx, OperationObjectRead, func(caller context.Context) (*struct{ private string }, error) {
			if caller != ctx || o.active != 1 {
				t.Fatal("measurement changed context or missed admitted activity")
			}
			return value, failure
		})
		if got != value || err != failure || o.active != 0 || len(o.events) != 1 || o.events[0].Operation != OperationObjectRead || o.events[0].Outcome != OutcomeForError(failure) || o.events[0].Duration < 0 {
			t.Fatal("measurement changed the result or lost its balanced observation", err, o.events)
		}
	}
}

func TestMeasurementPanicRemainsOriginalAndRecordsUncertain(t *testing.T) {
	o := &measurementObserver{}
	ctx := WithObserver(t.Context(), o)
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = MeasureError(ctx, OperationObjectWrite, func(context.Context) error { panic("PRIVATE_CALL_PANIC") })
	}()
	if recovered != "PRIVATE_CALL_PANIC" || o.active != 0 || len(o.events) != 1 || o.events[0].Outcome != OutcomeUncertain {
		t.Fatal("measurement swallowed panic or reported false success", recovered, o.events)
	}
}

func TestMeasurementFinalizationIsOnceAndNamesAreFinite(t *testing.T) {
	o := &measurementObserver{}
	ctx := WithObserver(t.Context(), o)
	finish := Start(ctx, Operation("PRIVATE_OPERATION"))
	var joined sync.WaitGroup
	for range 32 {
		joined.Go(func() { finish(OutcomeSucceeded, 3) })
	}
	joined.Wait()
	if o.active != 0 || len(o.events) != 1 || o.events[0].Attempt != 3 || o.events[0].Operation != OperationUnknown || len(o.operations) != 1 || o.operations[0] != OperationUnknown {
		t.Fatal("concurrent finalization expanded names or counted twice", o.events)
	}
}

func TestMeasurementFaultyOrMissingObserverCannotChangeCalls(t *testing.T) {
	for _, observer := range []Observer{nil, (*measurementObserver)(nil), &measurementObserver{panicBegin: true}, &measurementObserver{panicEnd: true}} {
		ctx := WithObserver(t.Context(), observer)
		if value, err := Measure(ctx, OperationObjectRead, func(context.Context) (int, error) { return 7, nil }); value != 7 || err != nil {
			t.Fatal("observer fault changed a business result", err)
		}
	}
}
