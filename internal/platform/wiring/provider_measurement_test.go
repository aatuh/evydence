package wiring

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type providerActivityFixture struct {
	active int
	events []telemetry.Event
}

func (f *providerActivityFixture) Begin(telemetry.Operation) func() {
	f.active++
	return func() { f.active-- }
}
func (f *providerActivityFixture) Observe(_ context.Context, event telemetry.Event) {
	f.events = append(f.events, event)
}

func TestProviderMeasurementsTrackActualCallsAndPreservePanic(t *testing.T) {
	for _, failure := range []error{nil, errors.New("PRIVATE_PROVIDER_ERROR"), context.Canceled} {
		f := &providerActivityFixture{}
		ctx := telemetry.WithObserver(t.Context(), f)
		value, err := providerCall(ctx, func(caller context.Context, _ string) (string, error) {
			if caller != ctx || f.active != 1 {
				t.Fatal("provider context changed or activity did not start")
			}
			return "PRIVATE_PROVIDER_RESPONSE", failure
		}, "PRIVATE_PROVIDER_REQUEST", logging.Fields{OperationID: "provider_sign"})
		if value != "PRIVATE_PROVIDER_RESPONSE" || err != failure || f.active != 0 || len(f.events) != 1 || f.events[0].Outcome != telemetry.OutcomeForError(failure) {
			t.Fatal("provider measurement changed actual results", err, f.events)
		}
	}
	f := &providerActivityFixture{}
	ctx := telemetry.WithObserver(t.Context(), f)
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_, _ = providerCall(ctx, func(context.Context, string) (string, error) { panic("PRIVATE_PROVIDER_PANIC") }, "", logging.Fields{OperationID: "provider_sign"})
	}()
	if recovered != "PRIVATE_PROVIDER_PANIC" || f.active != 0 || len(f.events) != 1 || f.events[0].Outcome != telemetry.OutcomeUncertain {
		t.Fatal("provider panic became success or leaked active work", recovered, f.events)
	}
}
