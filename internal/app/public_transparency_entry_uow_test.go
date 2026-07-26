package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingPublicTransparencyEntryRepository struct{ FutureExtensionsRepository }

func (failingPublicTransparencyEntryRepository) InsertPublicTransparencyLogEntry(context.Context, domain.PublicTransparencyLogEntry) error {
	return errInjectedRepositoryFailure
}

func TestPublicTransparencyEntryUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	batch, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{})
	if err != nil {
		t.Fatalf("create Merkle batch: %v", err)
	}
	log, err := ledger.CreatePublicTransparencyLog(ctx, actor, CreatePublicTransparencyLogInput{Name: "public", Endpoint: "https://transparency.example.test", PublicKey: "public-key"})
	if err != nil {
		t.Fatalf("create public transparency log: %v", err)
	}
	checkpoint, err := ledger.CreateTransparencyCheckpoint(ctx, actor, CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "rfc3161", ExternalID: "checkpoint"})
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	entry, err := ledger.PublishPublicTransparencyLogEntry(ctx, actor, PublishPublicTransparencyLogEntryInput{LogID: log.ID, CheckpointID: checkpoint.ID, ExternalID: "entry"})
	if err != nil {
		t.Fatalf("publish public transparency entry: %v", err)
	}
	if _, ok := ledger.publicLogEntries[entry.ID]; !ok {
		t.Fatal("public transparency entry was not published after commit")
	}
	if got := len(ledger.chain[actor.TenantID]); got != chainEntriesBefore+1 {
		t.Fatalf("public transparency entry audit was not published after commit: got %d, want %d", got, chainEntriesBefore+1)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingPublicTransparencyEntryRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	beforeEntries, beforeChain := len(ledger.publicLogEntries), len(ledger.chain[actor.TenantID])
	if _, err := ledger.PublishPublicTransparencyLogEntry(ctx, actor, PublishPublicTransparencyLogEntryInput{LogID: log.ID, CheckpointID: checkpoint.ID, ExternalID: "failed"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed public transparency entry err=%v, want injected repository failure", err)
	}
	if len(ledger.publicLogEntries) != beforeEntries || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed public transparency entry published cached state")
	}
}
