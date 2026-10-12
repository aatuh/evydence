package httpapi

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	e "github.com/aatuh/evydence/internal/experimental/app"
)

func TestTransparencyFixturePublishesRepositoryCheckpointWithoutAggregatePublication(t *testing.T) {
	ledger, factory, _ := transparencyRegressionLedger()
	owner := seedTransparencyFixtureScope(t, ledger, "Native")
	cp := owner.checkpoint
	cp.ID = "repository-only-checkpoint"
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Integrity.InsertTransparencyCheckpoint(ctx, cp)
	}); err != nil {
		t.Fatal(err)
	}
	f := transparencyFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	v, err := f.PublishPublicTransparencyLogEntry(t.Context(), owner.actor, e.PublicTransparencyPublicationInput{LogID: owner.log.ID, CheckpointID: cp.ID, ExternalID: "native-entry"})
	if err != nil || v.CheckpointID != cp.ID || v.MerkleBatchID != owner.batch.ID || v.State != "published" || v.EntryHash == "" {
		t.Fatal("publication consulted stale checkpoint cache", v, err)
	}
	saved, err := factory.Snapshot()
	if err != nil || saved.PublicTransparencyEntries[v.ID].CheckpointID != cp.ID {
		t.Fatal("native publication lost committed checkpoint", err)
	}
}

func TestTransparencyNativeFixtureRebindRetainsFetcherAndFixedClock(t *testing.T) {
	first, _, fetcher := transparencyRegressionLedger()
	second, _, _ := transparencyRegressionLedger()
	s, err := newLegacyServerFixture(first)
	if err != nil {
		t.Fatal(err)
	}
	s.bindTransparencyFixtureResources(fetcher, transparencyFixtureClock())
	s.bindLegacyLedgerFixture(second)
	for _, port := range []any{s.publicTransparencyMetadata, s.publicTransparencyProofs, s.publicTransparencyFetch} {
		f, ok := port.(transparencyFixtureCommands)
		if !ok || f.ledger != second || f.fetcher != fetcher || f.clock == nil || !f.clock.Now().Equal(peripheralFixtureQueryClock()) {
			t.Fatal("rebinding lost explicit native fixture dependencies")
		}
	}
}
