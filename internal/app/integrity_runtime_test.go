package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
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
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "tenant payload lock", ObjectKey: "tenants/" + actor.TenantID + "/raw/sample.json", Mode: "governance", RetentionDays: 30})
	if err != nil {
		t.Fatalf("retention policy: %v", err)
	}
	if policy.ObjectKey == "" {
		t.Fatalf("policy missing object key: %#v", policy)
	}
	if _, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "bad key", ObjectKey: "tenants/other/raw/sample.json", Mode: "governance", RetentionDays: 30}); !errors.Is(err, ErrValidation) {
		t.Fatalf("foreign object key err=%v, want validation", err)
	}
	verifiedPolicy, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("verify retention: %v", err)
	}
	if verifiedPolicy.Status != "verified" || verifiedPolicy.VerifiedAt == nil {
		t.Fatalf("verified policy = %#v", verifiedPolicy)
	}
	if len(verifiedPolicy.VerificationChecks) == 0 || len(verifiedPolicy.VerificationLimitations) == 0 {
		t.Fatalf("expected local retention verification limitations: %#v", verifiedPolicy)
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

func TestObjectRetentionVerifierRecordsProviderChecks(t *testing.T) {
	verifier := &fakeObjectRetentionVerifier{result: ObjectRetentionResult{
		Provider: "s3",
		Enforced: true,
		Checks: []domain.VerifyCheck{
			{Name: "s3_bucket_versioning", Result: "passed"},
			{Name: "s3_object_lock_mode", Result: "passed"},
		},
		Limitations: []string{"Bucket-level settings checked only."},
	}}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Retention: verifier})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "objects", Mode: "compliance", RetentionDays: 90})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	verified, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("verify policy: %v", err)
	}
	if verified.Status != "verified" || verified.VerificationHash == "" {
		t.Fatalf("verified policy = %#v", verified)
	}
	if len(verifier.requests) != 1 || verifier.requests[0].ObjectPrefix != "tenants/"+actor.TenantID+"/" {
		t.Fatalf("verifier requests = %#v", verifier.requests)
	}
	if len(verified.VerificationChecks) != 2 || verified.VerificationChecks[0].Name != "s3_bucket_versioning" {
		t.Fatalf("checks = %#v", verified.VerificationChecks)
	}
}

func TestObjectRetentionVerifierMarksProviderFailure(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Retention: &fakeObjectRetentionVerifier{result: ObjectRetentionResult{
		Provider:    "s3",
		Enforced:    false,
		Checks:      []domain.VerifyCheck{{Name: "s3_object_lock_retention", Result: "failed"}},
		Limitations: []string{"Bucket default retention is shorter than requested."},
	}}})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "objects", Mode: "governance", RetentionDays: 365})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	verified, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("verify policy: %v", err)
	}
	if verified.Status != "not_enforced" || verified.VerificationChecks[0].Result != "failed" {
		t.Fatalf("verified policy = %#v", verified)
	}
}

type fakeObjectRetentionVerifier struct {
	result   ObjectRetentionResult
	err      error
	requests []ObjectRetentionRequest
}

func (f *fakeObjectRetentionVerifier) VerifyObjectRetention(_ context.Context, req ObjectRetentionRequest) (ObjectRetentionResult, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return ObjectRetentionResult{}, f.err
	}
	return f.result, nil
}

func TestBackupRestoreRehearsalPreservesLedgerAndObjectPayloads(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	objects := newTestObjectStore()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store, ObjectStore: objects})
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments")
	if err != nil {
		t.Fatalf("product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "payments-api.tar.gz", "application/gzip", sampleDigest("artifact"), 123)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:oci/api"}]}`))
	if err != nil {
		t.Fatalf("upload sbom: %v", err)
	}
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("release bundle: %v", err)
	}
	manifest, err := ledger.GenerateBackupManifest(ctx, actor)
	if err != nil {
		t.Fatalf("backup manifest: %v", err)
	}
	if manifest.StateHash == "" || manifest.ResourceCounts["evidence"] == 0 {
		t.Fatalf("manifest missing restore-relevant counts: %#v", manifest)
	}

	dbBackup, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load backed-up state ok=%v err=%v", ok, err)
	}
	objectBackup := map[string]Object{}
	for key, object := range objects.objects {
		objectBackup[key] = object
	}
	restoredStore := NewMemoryStore()
	if err := restoredStore.SaveState(ctx, dbBackup); err != nil {
		t.Fatalf("restore state: %v", err)
	}
	restoredObjects := &testObjectStore{objects: objectBackup}
	restored := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: restoredStore, ObjectStore: restoredObjects})

	restoredActor, err := restored.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate restored api key: %v", err)
	}
	if _, err := restored.VerifyBackupManifest(ctx, restoredActor, manifest.ID); err != nil {
		t.Fatalf("verify restored backup manifest: %v", err)
	}
	restoredSBOM, err := restored.GetSBOM(ctx, restoredActor, sbom.ID)
	if err != nil || restoredSBOM.ComponentCount != sbom.ComponentCount {
		t.Fatalf("restored sbom = %#v err=%v", restoredSBOM, err)
	}
	evidence, err := restored.GetEvidence(ctx, restoredActor, restoredSBOM.EvidenceID)
	if err != nil {
		t.Fatalf("restored evidence: %v", err)
	}
	payloadKey := strings.TrimPrefix(evidence.PayloadRef, "object://")
	if payloadKey == "" {
		t.Fatalf("restored evidence missing payload ref: %#v", evidence)
	}
	if object, err := restoredObjects.Get(ctx, payloadKey); err != nil || object.Digest != evidence.PayloadHash {
		t.Fatalf("restored object digest=%q err=%v want %q", object.Digest, err, evidence.PayloadHash)
	}
	if vr, err := restored.VerifySubject(ctx, restoredActor, "release_bundle", bundle.ID); err != nil || vr.Result != "passed" {
		t.Fatalf("verify restored bundle = %#v err=%v", vr, err)
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
