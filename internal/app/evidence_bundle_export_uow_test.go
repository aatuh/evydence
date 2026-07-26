package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingEvidenceBundleRepository struct{ PackageRepository }

func (failingEvidenceBundleRepository) InsertEvidenceBundle(context.Context, domain.EvidenceBundle) error {
	return errInjectedRepositoryFailure
}

type failingReleaseBundleRepository struct{ PackageRepository }

func (failingReleaseBundleRepository) InsertReleaseBundle(context.Context, domain.ReleaseBundle) error {
	return errInjectedRepositoryFailure
}

func TestReleaseBundleUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Release bundle", "release-bundle")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	beforeAudit := len(ledger.chain[actor.TenantID])
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("create release bundle: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after release bundle: %v", err)
	}
	if snapshot.ReleaseBundles[bundle.ID].ID != bundle.ID || len(bundle.SignatureRefs) != 1 || snapshot.Signatures[bundle.SignatureRefs[0]].ID != bundle.SignatureRefs[0] || len(snapshot.AuditEntries[actor.TenantID]) != beforeAudit+1 || len(snapshot.OutboxJobs) != 1 {
		t.Fatalf("release bundle was not committed atomically: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Packages = failingReleaseBundleRepository{PackageRepository: repositories.Packages}
		return repositories
	}}
	beforeBundles, beforeSignatures, beforeAudit := len(ledger.bundles), len(ledger.signatures), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateReleaseBundle(ctx, actor, release.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed release bundle err=%v, want injected repository failure", err)
	}
	if len(ledger.bundles) != beforeBundles || len(ledger.signatures) != beforeSignatures || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed release bundle published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed release bundle: %v", err)
	}
	if len(after.ReleaseBundles) != len(snapshot.ReleaseBundles) || len(after.Signatures) != len(snapshot.Signatures) || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) || len(after.OutboxJobs) != len(snapshot.OutboxJobs) {
		t.Fatalf("failed release bundle published durable state: before=%#v after=%#v", snapshot, after)
	}
}

func TestEvidenceBundleExportUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Evidence bundle", "evidence-bundle")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, ReleaseID: release.ID, Type: "sbom", Title: "Bundle evidence", PayloadHash: sampleDigest("bundle-evidence")})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	beforeAudit := len(ledger.chain[actor.TenantID])
	bundle, err := ledger.ExportEvidenceBundle(ctx, actor, release.ID, []string{evidence.ID})
	if err != nil {
		t.Fatalf("export evidence bundle: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after evidence bundle export: %v", err)
	}
	if snapshot.EvidenceBundles[bundle.ID].ID != bundle.ID || len(bundle.SignatureRefs) != 1 || snapshot.Signatures[bundle.SignatureRefs[0]].ID != bundle.SignatureRefs[0] || len(snapshot.AuditEntries[actor.TenantID]) != beforeAudit+1 {
		t.Fatalf("evidence bundle export was not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Packages = failingEvidenceBundleRepository{PackageRepository: repositories.Packages}
		return repositories
	}}
	beforeBundles, beforeSignatures, beforeAudit := len(ledger.evidenceBundles), len(ledger.signatures), len(ledger.chain[actor.TenantID])
	if _, err := ledger.ExportEvidenceBundle(ctx, actor, release.ID, []string{evidence.ID}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed evidence bundle export err=%v, want injected repository failure", err)
	}
	if len(ledger.evidenceBundles) != beforeBundles || len(ledger.signatures) != beforeSignatures || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed evidence bundle export published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed evidence bundle export: %v", err)
	}
	if len(after.EvidenceBundles) != len(snapshot.EvidenceBundles) || len(after.Signatures) != len(snapshot.Signatures) || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) {
		t.Fatalf("failed evidence bundle export published durable state: before=%#v after=%#v", snapshot, after)
	}
}
