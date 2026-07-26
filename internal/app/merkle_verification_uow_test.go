package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingMerkleVerificationRepository struct{ VerificationRepository }

func (failingMerkleVerificationRepository) InsertVerificationResult(context.Context, domain.VerificationResult) error {
	return errInjectedRepositoryFailure
}

func TestMerkleVerificationUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	batch, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{})
	if err != nil {
		t.Fatalf("create Merkle batch: %v", err)
	}
	verification, err := ledger.VerifyMerkleBatch(ctx, actor, batch.ID)
	if err != nil {
		t.Fatalf("verify Merkle batch: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got, ok := snapshot.VerificationResults[verification.ID]; !ok || got.SubjectID != batch.ID || got.TenantID != actor.TenantID {
		t.Fatalf("Merkle verification not committed: %#v", snapshot.VerificationResults)
	}
	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Verification = failingMerkleVerificationRepository{VerificationRepository: repositories.Verification}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failure: %v", err)
	}
	beforeVerifications := len(ledger.verifications)
	if _, err := ledger.VerifyMerkleBatch(ctx, actor, batch.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed Merkle verification err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failure: %v", err)
	}
	if len(after.VerificationResults) != len(before.VerificationResults) || len(ledger.verifications) != beforeVerifications {
		t.Fatalf("failed Merkle verification published state: before=%#v after=%#v", before, after)
	}
}
