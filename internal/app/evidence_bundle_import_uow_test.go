package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingEvidenceBundleImportRepository struct{ PackageRepository }

func (failingEvidenceBundleImportRepository) InsertEvidenceBundleImport(context.Context, domain.EvidenceBundleImport) error {
	return errInjectedRepositoryFailure
}

func TestEvidenceBundleImportUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	manifest := map[string]any{"bundle_version": domain.EvidenceBundleSchemaVersion, "evidence_ids": []string{"evi-1"}}
	hash, err := canonicalAnyHash(manifest)
	if err != nil {
		t.Fatalf("hash imported bundle manifest: %v", err)
	}
	bundle := domain.EvidenceBundle{TenantID: actor.TenantID, EvidenceIDs: []string{"evi-1"}, Manifest: manifest, ManifestHash: hash}
	auditEntriesBefore := len(ledger.chain[actor.TenantID])
	record, err := ledger.ImportEvidenceBundle(ctx, actor, bundle)
	if err != nil {
		t.Fatalf("import evidence bundle: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after evidence bundle import: %v", err)
	}
	if snapshot.BundleImports[record.ID].ID != record.ID || len(snapshot.AuditEntries[actor.TenantID]) != auditEntriesBefore+1 {
		t.Fatalf("evidence bundle import was not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Packages = failingEvidenceBundleImportRepository{PackageRepository: repositories.Packages}
		return repositories
	}}
	beforeImports, beforeAudit := len(ledger.bundleImports), len(ledger.chain[actor.TenantID])
	if _, err := ledger.ImportEvidenceBundle(ctx, actor, bundle); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed evidence bundle import err=%v, want injected repository failure", err)
	}
	if len(ledger.bundleImports) != beforeImports || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed evidence bundle import published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed evidence bundle import: %v", err)
	}
	if len(after.BundleImports) != len(snapshot.BundleImports) || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) {
		t.Fatalf("failed evidence bundle import published durable state: before=%#v after=%#v", snapshot, after)
	}
}
