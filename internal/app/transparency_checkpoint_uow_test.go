package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingTransparencyCheckpointRepository struct{ IntegrityRepository }

func (failingTransparencyCheckpointRepository) InsertTransparencyCheckpoint(context.Context, domain.TransparencyCheckpoint) error {
	return errInjectedRepositoryFailure
}

func TestTransparencyCheckpointUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	batch, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{})
	if err != nil {
		t.Fatalf("create Merkle batch: %v", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Integrity.InsertMerkleBatch(ctx, batch)
	}); err != nil {
		t.Fatalf("seed Merkle batch: %v", err)
	}
	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	checkpoint, err := ledger.CreateTransparencyCheckpoint(ctx, actor, CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "internal-rfc3161", ExternalID: "checkpoint-1"})
	if err != nil {
		t.Fatalf("create transparency checkpoint: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got, ok := snapshot.TransparencyCheckpoints[checkpoint.ID]; !ok || got.BatchID != batch.ID || got.TenantID != actor.TenantID {
		t.Fatalf("checkpoint not committed: %#v", snapshot.TransparencyCheckpoints)
	}
	if got := len(ledger.chain[actor.TenantID]); got != chainEntriesBefore+1 {
		t.Fatalf("checkpoint audit entry was not published after commit: got %d, want %d", got, chainEntriesBefore+1)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Integrity.InsertTransparencyCheckpoint(ctx, domain.TransparencyCheckpoint{})
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid checkpoint err=%v, want validation", err)
	}
	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Integrity = failingTransparencyCheckpointRepository{IntegrityRepository: repositories.Integrity}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failure: %v", err)
	}
	if _, err := ledger.CreateTransparencyCheckpoint(ctx, actor, CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "internal-rfc3161", ExternalID: "checkpoint-failed"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed checkpoint err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failure: %v", err)
	}
	if len(after.TransparencyCheckpoints) != len(before.TransparencyCheckpoints) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || len(ledger.transparency) != len(before.TransparencyCheckpoints) || len(ledger.chain[actor.TenantID]) != chainEntriesBefore+1 {
		t.Fatalf("failed checkpoint published state: before=%#v after=%#v", before, after)
	}
}
