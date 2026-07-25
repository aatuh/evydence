package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type failingRetentionRepository struct{ GovernanceRepository }

func (failingRetentionRepository) InsertLegalHold(context.Context, domain.LegalHold) error {
	return errInjectedRepositoryFailure
}

func (failingRetentionRepository) InsertRetentionOverride(context.Context, domain.RetentionOverride) error {
	return errInjectedRepositoryFailure
}

func TestRetentionWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Retention API", "retention-api")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, ReleaseID: release.ID, Type: "sbom", Title: "Retention evidence", PayloadHash: sampleDigest("retention-uow")})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	hold, err := ledger.CreateLegalHold(ctx, actor, CreateLegalHoldInput{ScopeType: "release", ScopeID: release.ID, Reason: "customer dispute", Owner: "legal"})
	if err != nil {
		t.Fatalf("create legal hold: %v", err)
	}
	override, err := ledger.CreateRetentionOverride(ctx, actor, CreateRetentionOverrideInput{ScopeType: "evidence", ScopeID: evidence.ID, RetentionUntil: fixedNow().Add(time.Hour), Reason: "extended review", Owner: "security"})
	if err != nil {
		t.Fatalf("create retention override: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := snapshot.LegalHolds[hold.ID]; !ok {
		t.Fatalf("legal hold is not committed: %#v", snapshot)
	}
	if _, ok := snapshot.RetentionOverrides[override.ID]; !ok {
		t.Fatalf("retention override is not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Governance = failingRetentionRepository{GovernanceRepository: repositories.Governance}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failures: %v", err)
	}
	if _, err := ledger.CreateLegalHold(ctx, actor, CreateLegalHoldInput{ScopeType: "release", ScopeID: release.ID, Reason: "must not publish", Owner: "legal"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed legal hold write err=%v", err)
	}
	if _, err := ledger.CreateRetentionOverride(ctx, actor, CreateRetentionOverrideInput{ScopeType: "evidence", ScopeID: evidence.ID, RetentionUntil: fixedNow().Add(2 * time.Hour), Reason: "must not publish", Owner: "security"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed retention override write err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failures: %v", err)
	}
	if len(after.LegalHolds) != len(before.LegalHolds) || len(after.RetentionOverrides) != len(before.RetentionOverrides) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) {
		t.Fatalf("retention repository failure published state: before=%#v after=%#v", before, after)
	}
}
