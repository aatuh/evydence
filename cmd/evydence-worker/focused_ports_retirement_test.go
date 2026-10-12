package main

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

// These ports deliberately expose only retired capabilities. The worker must
// reject them rather than invoking an aggregate read or an unfenced write.
type legacyWorkerPortTrap struct{ loads, saves, mutations int }

func (f *legacyWorkerPortTrap) LoadState(context.Context) (app.PersistedState, bool, error) {
	f.loads++
	return app.PersistedState{}, true, nil
}
func (f *legacyWorkerPortTrap) SaveState(context.Context, app.PersistedState) error {
	f.saves++
	return nil
}
func (f *legacyWorkerPortTrap) ApplyReleaseLedgerMutation(context.Context, app.ReleaseLedgerMutation) error {
	f.mutations++
	return nil
}

func TestWorkerNeverInvokesRetiredAggregateReadOrWritePorts(t *testing.T) {
	job := postgres.ClaimedJob{ID: "job", TenantID: "tenant", Kind: "parse_sbom", SubjectID: "sbom", LeaseToken: "lease"}
	t.Run("aggregate read", func(t *testing.T) {
		trap := &legacyWorkerPortTrap{}
		if _, _, err := loadOutboxJobState(t.Context(), trap, job); err == nil || trap.loads != 0 {
			t.Fatalf("worker used retired aggregate loader: err=%v calls=%d", err, trap.loads)
		}
	})
	t.Run("unclaimed mutation", func(t *testing.T) {
		trap := &legacyWorkerPortTrap{}
		if err := persistParserSideEffects(t.Context(), trap, job, app.ReleaseLedgerMutation{}); err == nil || trap.saves != 0 || trap.mutations != 0 {
			t.Fatalf("worker used retired write port: err=%v saves=%d mutations=%d", err, trap.saves, trap.mutations)
		}
	})
}

func TestClaimedParserPublicationRejectsCancellationAndTypedNilBeforeWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	store := &fakeClaimedReleaseLedgerMutationStore{}
	if err := persistParserSideEffects(ctx, store, postgres.ClaimedJob{ID: "job"}, app.ReleaseLedgerMutation{}); !errors.Is(err, context.Canceled) || store.jobID != "" {
		t.Fatalf("cancelled parser publication reached storage: err=%v job=%q", err, store.jobID)
	}
	var missing *fakeClaimedReleaseLedgerMutationStore
	if err := persistParserSideEffects(t.Context(), missing, postgres.ClaimedJob{}, app.ReleaseLedgerMutation{}); err == nil {
		t.Fatal("typed-nil claimed writer accepted")
	}
	if err := persistParserSideEffects(nil, store, postgres.ClaimedJob{ID: "job"}, app.ReleaseLedgerMutation{}); err == nil || store.jobID != "" { //nolint:staticcheck // Defensive nil-context rejection.
		t.Fatal("nil context reached claimed storage", err)
	}
}

func TestScopedParserReadRejectsTypedNilAndCancellationBeforeStorage(t *testing.T) {
	job := postgres.ClaimedJob{ID: "job", TenantID: "tenant", Kind: "parse_sbom", SubjectID: "sbom", LeaseToken: "lease"}
	var missing *fakeFocusedParserStateStore
	if _, _, err := loadOutboxJobState(t.Context(), missing, job); err == nil {
		t.Fatal("typed-nil scoped reader accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	store := &fakeFocusedParserStateStore{}
	if _, _, err := loadOutboxJobState(ctx, store, job); !errors.Is(err, context.Canceled) || len(store.focusedJobs) != 0 || store.loadCalls != 0 {
		t.Fatal("cancelled scoped read reached storage", err, store)
	}
}
