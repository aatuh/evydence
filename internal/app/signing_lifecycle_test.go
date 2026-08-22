package app

import (
	"context"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestSigningKeyLifecycleUsesInjectedClockAndDistinguishesCompromise(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 15, 12, 34, 56, 0, time.UTC)
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: func() time.Time { return now }})
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("create release bundle: %v", err)
	}
	keys, err := ledger.ListSigningKeys(ctx, actor)
	if err != nil || len(keys) != 1 {
		t.Fatalf("list signing keys=%#v err=%v", keys, err)
	}
	original := keys[0]
	if original.KID != "20260815T123456Z-v1" || !original.ValidFrom.Equal(now) || original.Version != 1 || original.Provider != domain.SigningKeyDefaultProvider {
		t.Fatalf("initial signing key lifecycle=%#v", original)
	}
	rotated, err := ledger.RotateSigningKey(ctx, actor, "scheduled rotation")
	if err != nil {
		t.Fatalf("rotate signing key: %v", err)
	}
	if rotated.Version != 2 || rotated.Provider != domain.SigningKeyDefaultProvider || rotated.PublicKeyFingerprint == "" {
		t.Fatalf("rotated signing key lifecycle=%#v", rotated)
	}
	if got := ledger.signingKeys[original.ID]; got.Status != domain.SigningKeyStatusRetiring || got.ValidUntil == nil || !got.ValidUntil.Equal(now) {
		t.Fatalf("retired signing key=%#v", got)
	}
	if _, err := ledger.RevokeSigningKey(ctx, actor, original.ID, "routine retirement"); err != nil {
		t.Fatalf("ordinary revoke: %v", err)
	}
	if _, err := ledger.VerifySubject(ctx, actor, "release_bundle", bundle.ID); err != nil {
		t.Fatalf("ordinary revocation must preserve valid historical signature: %v", err)
	}
	compromisedBundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("create release bundle with rotated key: %v", err)
	}
	if _, err := ledger.RevokeSigningKeyWithPolicy(ctx, actor, rotated.ID, SigningKeyRevocationInput{
		Reason:                   "confirmed compromise",
		Semantics:                domain.SigningKeyRevocationCompromised,
		HistoricalValidityPolicy: domain.SigningKeyHistoricalValidityInvalidateAll,
	}); err != nil {
		t.Fatalf("compromise revoke: %v", err)
	}
	if _, err := ledger.VerifySubject(ctx, actor, "release_bundle", compromisedBundle.ID); err == nil {
		t.Fatal("compromised signing key must invalidate historical bundle signature under invalidate-all policy")
	}
}

func TestMemorySigningKeyRepositoryAllowsOnlyOneActiveKeyPerProvider(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	tenant := domain.Tenant{ID: "ten_key_lifecycle", Name: "Key Lifecycle", CreatedAt: fixedNow()}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		if err := repositories.Identity.InsertTenant(ctx, tenant); err != nil {
			return err
		}
		return repositories.Signatures.InsertSigningKey(ctx, domain.SigningKey{ID: "key_one", TenantID: tenant.ID, KID: "one", Version: 1, Provider: domain.SigningKeyDefaultProvider, Algorithm: "Ed25519", Status: domain.SigningKeyStatusActive, PublicKey: "public-one", PublicKeyFingerprint: "sha256:one", ValidFrom: fixedNow(), CreatedAt: fixedNow()})
	}); err != nil {
		t.Fatalf("seed active key: %v", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Signatures.InsertSigningKey(ctx, domain.SigningKey{ID: "key_two", TenantID: tenant.ID, KID: "two", Version: 2, Provider: domain.SigningKeyDefaultProvider, Algorithm: "Ed25519", Status: domain.SigningKeyStatusActive, PublicKey: "public-two", PublicKeyFingerprint: "sha256:two", ValidFrom: fixedNow(), CreatedAt: fixedNow()})
	}); err == nil {
		t.Fatal("second active signing key for the same provider was accepted")
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		retired := domain.SigningKey{ID: "key_one", TenantID: tenant.ID, KID: "one", Version: 1, Provider: domain.SigningKeyDefaultProvider, Algorithm: "Ed25519", Status: domain.SigningKeyStatusRetiring, PublicKey: "public-one", PublicKeyFingerprint: "sha256:one", Private: []byte("private-one"), ValidFrom: fixedNow(), ValidUntil: signingTimePointer(fixedNow()), CreatedAt: fixedNow()}
		return repositories.Signatures.UpdateSigningKey(ctx, retired, domain.SigningKeyStatusActive)
	}); err != nil {
		t.Fatalf("retire initial active key: %v", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Signatures.InsertSigningKey(ctx, domain.SigningKey{ID: "key_two", TenantID: tenant.ID, KID: "two", Version: 2, Provider: domain.SigningKeyDefaultProvider, Algorithm: "Ed25519", Status: domain.SigningKeyStatusActive, PublicKey: "public-two", PublicKeyFingerprint: "sha256:two", Private: []byte("private-two"), ValidFrom: fixedNow(), CreatedAt: fixedNow()})
	}); err != nil {
		t.Fatalf("replacement active key: %v", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Signatures.UpdateSigningKey(ctx, domain.SigningKey{ID: "key_one", TenantID: tenant.ID, KID: "one", Version: 1, Provider: domain.SigningKeyDefaultProvider, Algorithm: "Ed25519", Status: domain.SigningKeyStatusActive, PublicKey: "public-one", PublicKeyFingerprint: "sha256:one", ValidFrom: fixedNow(), CreatedAt: fixedNow()}, domain.SigningKeyStatusRetiring)
	}); err == nil {
		t.Fatal("retired key was reactivated while a replacement key is active")
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Signatures.UpdateSigningKey(ctx, domain.SigningKey{ID: "key_two", TenantID: tenant.ID, KID: "two", Version: 2, Provider: domain.SigningKeyDefaultProvider, Algorithm: "Ed25519", Status: domain.SigningKeyStatusRevoked, PublicKey: "public-two", PublicKeyFingerprint: "sha256:two", ValidFrom: fixedNow(), ValidUntil: signingTimePointer(fixedNow()), CreatedAt: fixedNow()}, domain.SigningKeyStatusActive)
	}); err != nil {
		t.Fatalf("revoke replacement key: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot lifecycle: %v", err)
	}
	if got := string(snapshot.SigningKeys["key_two"].Private); got != "private-two" {
		t.Fatalf("update discarded private material=%q", got)
	}
}

func signingTimePointer(value time.Time) *time.Time { return &value }
