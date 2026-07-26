package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingNewSigningKeyRepository struct{ SignatureRepository }

func (failingNewSigningKeyRepository) InsertSigningKey(context.Context, domain.SigningKey) error {
	return errInjectedRepositoryFailure
}

type failingSigningKeyRepository struct{ SignatureRepository }

func (failingSigningKeyRepository) UpdateSigningKey(context.Context, domain.SigningKey, string) error {
	return errInjectedRepositoryFailure
}

func TestSigningKeyRotationAndRevocationUseUnitOfWork(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	keys, err := ledger.ListSigningKeys(ctx, actor)
	if err != nil || len(keys) != 1 {
		t.Fatalf("initial signing keys=%#v err=%v", keys, err)
	}
	previous := keys[0]
	beforeRotation, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before rotation: %v", err)
	}
	rotated, err := ledger.RotateSigningKey(ctx, actor, "scheduled rotation")
	if err != nil {
		t.Fatalf("rotate signing key: %v", err)
	}
	if rotated.Private != nil || rotated.Status != "active" {
		t.Fatalf("rotated public key=%#v", rotated)
	}
	afterRotation, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after rotation: %v", err)
	}
	if got := afterRotation.SigningKeys[previous.ID]; got.Status != "retiring" {
		t.Fatalf("previous signing key after rotation=%#v", got)
	}
	if got, ok := afterRotation.SigningKeys[rotated.ID]; !ok || got.Status != "active" || len(got.Private) == 0 {
		t.Fatalf("rotated signing key was not committed: %#v", afterRotation.SigningKeys)
	}
	if len(afterRotation.AuditEntries[actor.TenantID]) != len(beforeRotation.AuditEntries[actor.TenantID])+1 {
		t.Fatalf("rotation audit was not committed with key state: before=%#v after=%#v", beforeRotation.AuditEntries, afterRotation.AuditEntries)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		stale := afterRotation.SigningKeys[rotated.ID]
		stale.Status = "retiring"
		return repositories.Signatures.UpdateSigningKey(ctx, stale, "retiring")
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale signing key update err=%v, want conflict", err)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Signatures = failingNewSigningKeyRepository{SignatureRepository: repositories.Signatures}
		return repositories
	}}
	beforeFailedRotation, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failed rotation: %v", err)
	}
	beforeKeyCount := len(ledger.signingKeys)
	if _, err := ledger.RotateSigningKey(ctx, actor, "must not publish"); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed rotation err=%v", err)
	}
	afterFailedRotation, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed rotation: %v", err)
	}
	if len(afterFailedRotation.SigningKeys) != len(beforeFailedRotation.SigningKeys) || len(afterFailedRotation.AuditEntries[actor.TenantID]) != len(beforeFailedRotation.AuditEntries[actor.TenantID]) || len(ledger.signingKeys) != beforeKeyCount {
		t.Fatalf("failed rotation published state: before=%#v after=%#v", beforeFailedRotation, afterFailedRotation)
	}

	ledger.unitOfWork = memory
	revoked, err := ledger.RevokeSigningKey(ctx, actor, rotated.ID, "retire rotated key")
	if err != nil {
		t.Fatalf("revoke signing key: %v", err)
	}
	if revoked.Private != nil || revoked.Status != "revoked" || revoked.RevokedAt == nil {
		t.Fatalf("revoked public key=%#v", revoked)
	}
	afterRevoke, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after revoke: %v", err)
	}
	if got := afterRevoke.SigningKeys[rotated.ID]; got.Status != "revoked" || got.RevokedAt == nil {
		t.Fatalf("revoked signing key was not committed: %#v", got)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Signatures = failingSigningKeyRepository{SignatureRepository: repositories.Signatures}
		return repositories
	}}
	beforeFailedRevoke, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failed revoke: %v", err)
	}
	if _, err := ledger.RevokeSigningKey(ctx, actor, previous.ID, "must not publish"); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed revoke err=%v", err)
	}
	afterFailedRevoke, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed revoke: %v", err)
	}
	if len(afterFailedRevoke.AuditEntries[actor.TenantID]) != len(beforeFailedRevoke.AuditEntries[actor.TenantID]) || afterFailedRevoke.SigningKeys[previous.ID].Status != beforeFailedRevoke.SigningKeys[previous.ID].Status || ledger.signingKeys[previous.ID].Status != beforeFailedRevoke.SigningKeys[previous.ID].Status {
		t.Fatalf("failed revocation published state: before=%#v after=%#v", beforeFailedRevoke, afterFailedRevoke)
	}
}
