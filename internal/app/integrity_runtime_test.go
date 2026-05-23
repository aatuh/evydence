package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCosignMerkleTransparencyAndKeyRevocationFlow(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	image, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.example.com/payments", Tag: "1.0.0", Digest: artifact.Digest})
	if err != nil {
		t.Fatalf("image: %v", err)
	}
	sig, err := ledger.CreateArtifactSignature(ctx, actor, CreateArtifactSignatureInput{ArtifactID: artifact.ID, Algorithm: "cosign", Signature: "MEUCIQDexample"})
	if err != nil {
		t.Fatalf("artifact signature: %v", err)
	}
	cosign, err := ledger.VerifyCosignSignature(ctx, actor, VerifyCosignInput{ArtifactSignatureID: sig.ID, RekorUUID: "rekor-uuid", RekorLogIndex: "42", CertificateIdentity: "repo:owner/name", CertificateIssuer: "https://token.actions.githubusercontent.com"})
	if err != nil {
		t.Fatalf("cosign verify: %v", err)
	}
	if cosign.ContainerImageID != image.ID || cosign.Result != "passed" {
		t.Fatalf("cosign verification = %#v", cosign)
	}
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	keys, err := ledger.ListSigningKeys(ctx, actor)
	if err != nil || len(keys) == 0 {
		t.Fatalf("signing keys: %#v %v", keys, err)
	}
	if _, err := ledger.RevokeSigningKey(ctx, actor, keys[len(keys)-1].ID, "rotation test"); err != nil {
		t.Fatalf("revoke signing key: %v", err)
	}
	vr, err := ledger.VerifySubject(ctx, actor, "release_bundle", bundle.ID)
	if err != nil {
		t.Fatalf("historical signature should verify after revocation: %v", err)
	}
	if vr.Result != "passed" {
		t.Fatalf("verification result = %s", vr.Result)
	}
	batch, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{})
	if err != nil {
		t.Fatalf("merkle batch: %v", err)
	}
	if batch.EntryCount == 0 || batch.RootHash == "" {
		t.Fatalf("batch = %#v", batch)
	}
	if _, err := ledger.VerifyMerkleBatch(ctx, actor, batch.ID); err != nil {
		t.Fatalf("verify merkle batch: %v", err)
	}
	checkpoint, err := ledger.CreateTransparencyCheckpoint(ctx, actor, CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "internal-rfc3161", ExternalID: "ts-1"})
	if err != nil {
		t.Fatalf("transparency checkpoint: %v", err)
	}
	if checkpoint.TimestampHash == "" {
		t.Fatal("expected timestamp hash")
	}
}

func TestRuntimeRetentionBackupReadinessMetricsAndAudit(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	if _, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "dev", Type: "local_encrypted_dev", KeyRef: "file://dev.keys", Encrypted: true}); err != nil {
		t.Fatalf("signing provider: %v", err)
	}
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "tenant payload lock", Mode: "governance", RetentionDays: 30})
	if err != nil {
		t.Fatalf("retention policy: %v", err)
	}
	verifiedPolicy, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("verify retention: %v", err)
	}
	if verifiedPolicy.Status != "verified" || verifiedPolicy.VerifiedAt == nil {
		t.Fatalf("verified policy = %#v", verifiedPolicy)
	}
	manifest, err := ledger.GenerateBackupManifest(ctx, actor)
	if err != nil {
		t.Fatalf("backup manifest: %v", err)
	}
	if manifest.StateHash == "" || manifest.ResourceCounts["audit_chain_entries"] == 0 {
		t.Fatalf("backup manifest = %#v", manifest)
	}
	if _, err := ledger.VerifyBackupManifest(ctx, actor, manifest.ID); err != nil {
		t.Fatalf("verify backup manifest: %v", err)
	}
	ready, err := ledger.ReadinessStatus(ctx)
	if err != nil || ready["status"] != "ok" {
		t.Fatalf("readiness = %#v err=%v", ready, err)
	}
	metrics, err := ledger.Metrics(ctx, actor)
	if err != nil || metrics["tenant_id"] != actor.TenantID {
		t.Fatalf("metrics = %#v err=%v", metrics, err)
	}
	entries, err := ledger.ListAuditLog(ctx, actor, AuditLogFilter{SubjectType: "release", SubjectID: release.ID, Since: ptrTime(fixedNow().Add(-time.Hour)), Limit: 10})
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected release audit entries")
	}
	_, _, otherSecret, err := ledger.BootstrapTenant(ctx, "Other", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap other: %v", err)
	}
	other, err := ledger.Authenticate(ctx, otherSecret)
	if err != nil {
		t.Fatalf("auth other: %v", err)
	}
	if _, err := ledger.VerifyObjectRetentionPolicy(ctx, other, policy.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant retention verify err = %v, want not found", err)
	}
}

func TestSigningProviderRejectsPlaintextLocalDev(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, _, _ := setupReleaseRiskFixture(t, ledger)
	_, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "bad", Type: "local_encrypted_dev", KeyRef: "file://dev.keys"})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v, want validation", err)
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
