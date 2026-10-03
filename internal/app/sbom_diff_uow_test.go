package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingSBOMDiffRepository struct{ RiskRepository }

func (failingSBOMDiffRepository) InsertSBOMDiff(context.Context, domain.SBOMDiff) error {
	return errInjectedRepositoryFailure
}

func TestSBOMDiffUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "SBOM diff", "sbom-diff")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "sbom.json", "application/json", sampleDigest("sbom-diff"), 1)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	base, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"base","version":"1"}]}`))
	if err != nil {
		t.Fatalf("upload base SBOM: %v", err)
	}
	target, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"target","version":"1"}]}`))
	if err != nil {
		t.Fatalf("upload target SBOM: %v", err)
	}
	beforeAudit := len(ledger.chain[actor.TenantID])
	diff, err := ledger.CreateSBOMDiff(ctx, actor, CreateSBOMDiffInput{BaseSBOMID: base.ID, TargetSBOMID: target.ID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("create SBOM diff: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after SBOM diff: %v", err)
	}
	if snapshot.SBOMDiffs[diff.ID].ID != diff.ID || len(snapshot.DependencyChanges) != len(diff.DependencyChanges) || len(snapshot.AuditEntries[actor.TenantID]) != beforeAudit+1 {
		t.Fatalf("SBOM diff was not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Risk = failingSBOMDiffRepository{RiskRepository: repositories.Risk}
		return repositories
	}}
	beforeDiffs, beforeChanges, beforeAudit := len(ledger.sbomDiffs), len(ledger.depChanges), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateSBOMDiff(ctx, actor, CreateSBOMDiffInput{BaseSBOMID: base.ID, TargetSBOMID: target.ID, ReleaseID: release.ID}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed SBOM diff err=%v, want injected repository failure", err)
	}
	if len(ledger.sbomDiffs) != beforeDiffs || len(ledger.depChanges) != beforeChanges || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed SBOM diff published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed SBOM diff: %v", err)
	}
	if len(after.SBOMDiffs) != len(snapshot.SBOMDiffs) || len(after.DependencyChanges) != len(snapshot.DependencyChanges) || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) {
		t.Fatalf("failed SBOM diff published durable state: before=%#v after=%#v", snapshot, after)
	}
}
