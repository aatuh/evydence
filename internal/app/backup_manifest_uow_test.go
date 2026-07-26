package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingBackupManifestRepository struct{ IntegrityRepository }

func (failingBackupManifestRepository) InsertBackupManifest(context.Context, domain.BackupManifest) error {
	return errInjectedRepositoryFailure
}

func TestBackupManifestUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	manifest, err := ledger.GenerateBackupManifest(ctx, actor)
	if err != nil {
		t.Fatalf("generate backup manifest: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got, ok := snapshot.BackupManifests[manifest.ID]; !ok || got.TenantID != actor.TenantID || got.StateHash != manifest.StateHash {
		t.Fatalf("backup manifest not committed: %#v", snapshot.BackupManifests)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Integrity.InsertBackupManifest(ctx, domain.BackupManifest{})
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid backup manifest err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Integrity.InsertBackupManifest(ctx, manifest)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate backup manifest err=%v, want conflict", err)
	}
	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Integrity = failingBackupManifestRepository{IntegrityRepository: repositories.Integrity}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failure: %v", err)
	}
	if _, err := ledger.GenerateBackupManifest(ctx, actor); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed backup manifest err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failure: %v", err)
	}
	if len(after.BackupManifests) != len(before.BackupManifests) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || len(ledger.backupManifests) != len(before.BackupManifests) {
		t.Fatalf("failed backup manifest published state: before=%#v after=%#v", before, after)
	}
}
