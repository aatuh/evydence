package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingPublicTransparencyLogRepository struct{ FutureExtensionsRepository }

func (failingPublicTransparencyLogRepository) InsertPublicTransparencyLog(context.Context, domain.PublicTransparencyLog) error {
	return errInjectedRepositoryFailure
}

func TestPublicTransparencyLogUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)

	chainEntriesBefore := len(ledger.chain[actor.TenantID])
	log, err := ledger.CreatePublicTransparencyLog(ctx, actor, CreatePublicTransparencyLogInput{Name: "public", Endpoint: "https://transparency.example.test", PublicKey: "public-key"})
	if err != nil {
		t.Fatalf("create public transparency log: %v", err)
	}
	if _, ok := ledger.publicLogs[log.ID]; !ok {
		t.Fatal("public transparency log was not published after commit")
	}
	if got := len(ledger.chain[actor.TenantID]); got != chainEntriesBefore+1 {
		t.Fatalf("public transparency log audit entry was not published after commit: got %d, want %d", got, chainEntriesBefore+1)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := snapshot.PublicTransparencyLogs[log.ID]; !ok {
		t.Fatal("public transparency log was not committed")
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Future = failingPublicTransparencyLogRepository{FutureExtensionsRepository: repositories.Future}
		return repositories
	}}
	beforeLogs, beforeChain := len(ledger.publicLogs), len(ledger.chain[actor.TenantID])
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failure: %v", err)
	}
	if _, err := ledger.CreatePublicTransparencyLog(ctx, actor, CreatePublicTransparencyLogInput{Name: "failed", Endpoint: "https://transparency.example.test", PublicKey: "public-key"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed public transparency log err=%v, want injected repository failure", err)
	}
	if len(ledger.publicLogs) != beforeLogs || len(ledger.chain[actor.TenantID]) != beforeChain {
		t.Fatal("failed public transparency log published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failure: %v", err)
	}
	if len(after.PublicTransparencyLogs) != len(before.PublicTransparencyLogs) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) {
		t.Fatal("failed public transparency log committed durable state")
	}
}
