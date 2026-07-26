package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingMerkleBatchRepository struct{ IntegrityRepository }

func (failingMerkleBatchRepository) InsertMerkleBatch(context.Context, domain.MerkleBatch) error {
	return errInjectedRepositoryFailure
}

func TestMerkleBatchUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	batch, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{})
	if err != nil {
		t.Fatalf("create Merkle batch: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got, ok := snapshot.MerkleBatches[batch.ID]; !ok || got.TenantID != actor.TenantID || got.RootHash != batch.RootHash {
		t.Fatalf("Merkle batch was not committed: %#v", snapshot.MerkleBatches)
	}
	if got := len(ledger.chain[actor.TenantID]); got != chainEntriesBefore+1 {
		t.Fatalf("Merkle batch audit entry was not published after commit: got %d, want %d", got, chainEntriesBefore+1)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Integrity = failingMerkleBatchRepository{IntegrityRepository: repositories.Integrity}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failure: %v", err)
	}
	if _, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed Merkle batch err=%v, want injected repository failure", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failure: %v", err)
	}
	if len(after.MerkleBatches) != len(before.MerkleBatches) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || len(ledger.merkleBatches) != len(before.MerkleBatches) || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatal("failed Merkle batch published state")
	}
}
