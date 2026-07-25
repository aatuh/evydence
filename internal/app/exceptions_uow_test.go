package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type failingExceptionRepository struct{ DecisionRepository }

func (failingExceptionRepository) InsertException(context.Context, domain.Exception) error {
	return errInjectedRepositoryFailure
}

func (failingExceptionRepository) ApproveException(context.Context, domain.Exception) error {
	return errInjectedRepositoryFailure
}

func TestExceptionWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Exceptions API", "exceptions-api")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	exception, err := ledger.CreateException(ctx, actor, CreateExceptionInput{ReleaseID: release.ID, Reason: "temporary exception", Owner: "security", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("create exception: %v", err)
	}
	exception, err = ledger.ApproveException(ctx, actor, exception.ID)
	if err != nil {
		t.Fatalf("approve exception: %v", err)
	}
	pending, err := ledger.CreateException(ctx, actor, CreateExceptionInput{ReleaseID: release.ID, Reason: "pending approval", Owner: "security", ExpiresAt: fixedNow().Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("create pending exception: %v", err)
	}

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if stored, ok := snapshot.Exceptions[exception.ID]; !ok || !stored.Approved || stored.ApprovedAt == nil {
		t.Fatalf("exception writes were not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Decisions = failingExceptionRepository{DecisionRepository: repositories.Decisions}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failures: %v", err)
	}
	if _, err := ledger.CreateException(ctx, actor, CreateExceptionInput{ReleaseID: release.ID, Reason: "must not publish", Owner: "security", ExpiresAt: fixedNow().Add(3 * time.Hour)}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed exception write err=%v", err)
	}
	if _, err := ledger.ApproveException(ctx, actor, pending.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed exception approval err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failures: %v", err)
	}
	if len(after.Exceptions) != len(before.Exceptions) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || ledger.exceptions[pending.ID].Approved {
		t.Fatalf("exception repository failure published state: before=%#v after=%#v", before, after)
	}
}
