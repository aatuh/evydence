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
	if cosign.ContainerImageID != image.ID || cosign.Result != "limited" {
		t.Fatalf("cosign verification = %#v", cosign)
	}
	if !hasVerifyCheck(cosign.Checks, "digest_binding_assessed", "passed") || !hasVerifyCheck(cosign.Checks, "signature_material_present", "passed") || !hasVerifyCheck(cosign.Checks, "rekor_metadata_present", "passed") {
		t.Fatalf("cosign metadata assessment checks = %#v", cosign.Checks)
	}
	full, err := ledger.VerifyCosignSignature(ctx, actor, VerifyCosignInput{ArtifactSignatureID: sig.ID, RequireFullVerification: true})
	if !errors.Is(err, ErrFullVerificationUnavailable) || full.Result != "limited" {
		t.Fatalf("full cosign verification = %#v err=%v", full, err)
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

func TestVerifyCosignSignatureRejectsHumanSessionOutsideArtifactGrant(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, _, artifact := setupReleaseRiskFixture(t, ledger)
	sig, err := ledger.CreateArtifactSignature(ctx, actor, CreateArtifactSignatureInput{ArtifactID: artifact.ID, Algorithm: "cosign", Signature: "recorded"})
	if err != nil {
		t.Fatalf("create artifact signature: %v", err)
	}
	restricted := domain.Actor{TenantID: actor.TenantID, UserID: "usr_restricted", Scopes: []string{ScopeVerifyRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_other", Scopes: []string{ScopeVerifyRead}}}}
	if _, err := ledger.VerifyCosignSignature(ctx, restricted, VerifyCosignInput{ArtifactSignatureID: sig.ID}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("restricted session verify err=%v, want forbidden", err)
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
	if _, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "legal hold without object", RequireLegalHold: true, Mode: "governance", RetentionDays: 30}); !errors.Is(err, ErrValidation) {
		t.Fatalf("legal hold without object err=%v, want validation", err)
	}
	verifiedPolicy, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("verify retention: %v", err)
	}
	if verifiedPolicy.Status != "not_verified" || verifiedPolicy.VerifiedAt == nil {
		t.Fatalf("local-only retention policy must not be provider verified: %#v", verifiedPolicy)
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
		Provider:      "s3",
		Bucket:        "evydence-test",
		Mode:          "compliance",
		RetentionDays: 90,
		ObservedAt:    fixedNow(),
		Enforced:      true,
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
	if !hasVerifyCheck(verified.VerificationChecks, "s3_bucket_versioning", "passed") || !hasVerifyCheck(verified.VerificationChecks, "provider_enforced_proof", "passed") {
		t.Fatalf("checks = %#v", verified.VerificationChecks)
	}
}

func TestSigningCustodyReviewAndObjectLockProofExports(t *testing.T) {
	verifier := &fakeObjectRetentionVerifier{result: ObjectRetentionResult{
		Provider:      "s3",
		Bucket:        "evydence-test",
		Mode:          "compliance",
		RetentionDays: 365,
		ObservedAt:    fixedNow(),
		Enforced:      true,
		Checks: []domain.VerifyCheck{
			{Name: "s3_bucket_versioning", Result: "passed"},
			{Name: "s3_object_lock_mode", Result: "passed"},
		},
		Limitations: []string{"Operator must review bucket IAM, lifecycle, and legal requirements."},
	}}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Retention: verifier})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)

	if _, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "bad native", Type: "native_pkcs11_hsm", KeyRef: "pkcs11:token=release;object=key;pin-value=1234", Encrypted: true}); !errors.Is(err, ErrValidation) {
		t.Fatalf("native provider with embedded PIN err=%v, want validation", err)
	}
	if _, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "bad native", Type: "native_pkcs11_hsm", KeyRef: "pkcs11:token=release;object=key"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("unencrypted native provider err=%v, want validation", err)
	}
	provider, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "native hsm", Type: "native_pkcs11_hsm", KeyRef: "pkcs11:token=release;object=evydence-signing-key", Encrypted: true})
	if err != nil {
		t.Fatalf("native provider: %v", err)
	}
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "release objects", ObjectPrefix: "tenants/" + actor.TenantID + "/raw/", Mode: "compliance", RetentionDays: 180})
	if err != nil {
		t.Fatalf("retention policy: %v", err)
	}
	verified, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("verify retention: %v", err)
	}
	report, err := ledger.SigningCustodyReviewReport(ctx, actor)
	if err != nil {
		t.Fatalf("custody report: %v", err)
	}
	if report.ReportType != "signing_custody_review" || len(report.SigningProviders) != 1 || report.SigningProviders[0].ID != provider.ID {
		t.Fatalf("custody report providers = %#v", report)
	}
	if len(report.ObjectRetentionPolicies) != 1 || report.ObjectRetentionPolicies[0].VerificationHash != verified.VerificationHash {
		t.Fatalf("custody report retention policies = %#v", report.ObjectRetentionPolicies)
	}
	for _, want := range []string{"production_signing_provider_recorded", "native_pkcs11_hsm_profile_recorded", "object_lock_proof_recorded"} {
		if !hasVerifyCheck(report.Checks, want, "passed") {
			t.Fatalf("custody report missing passed check %q: %#v", want, report.Checks)
		}
	}
	if !strings.Contains(strings.Join(report.Limitations, "\n"), "does not prove legal compliance") || strings.Contains(strings.Join(report.Limitations, "\n"), "certified secure") {
		t.Fatalf("unsafe custody limitations: %#v", report.Limitations)
	}

	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "object lock proof", AllowedTypes: []string{"object_lock_proof"}})
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: profile.ID, Title: "Object-lock proof package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("package: %v", err)
	}
	proofs, ok := pkg.Manifest["object_lock_proofs"].([]map[string]any)
	if !ok || len(proofs) != 1 || proofs[0]["verification_hash"] != verified.VerificationHash {
		t.Fatalf("package object-lock proofs = %#v", pkg.Manifest["object_lock_proofs"])
	}
	if _, ok := proofs[0]["object_key"]; ok {
		t.Fatalf("customer package object-lock proof exposed object key: %#v", proofs[0])
	}
	limitations, _ := proofs[0]["limitations"].([]string)
	if strings.Contains(strings.Join(limitations, "\n"), "secure release") {
		t.Fatalf("object-lock proof made unsafe claim: %#v", proofs[0])
	}

	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("release bundle: %v", err)
	}
	if proofs, ok := bundle.Manifest["object_lock_proofs"].([]map[string]any); !ok || len(proofs) != 1 || proofs[0]["verification_hash"] != verified.VerificationHash {
		t.Fatalf("release bundle object-lock proofs = %#v", bundle.Manifest["object_lock_proofs"])
	}
	evidenceBundle, err := ledger.ExportEvidenceBundle(ctx, actor, release.ID, nil)
	if err != nil {
		t.Fatalf("evidence bundle: %v", err)
	}
	if proofs, ok := evidenceBundle.Manifest["object_lock_proofs"].([]map[string]any); !ok || len(proofs) != 1 || proofs[0]["verification_hash"] != verified.VerificationHash {
		t.Fatalf("evidence bundle object-lock proofs = %#v", evidenceBundle.Manifest["object_lock_proofs"])
	}
}

func TestObjectRetentionVerifierReceivesLegalHoldRequirement(t *testing.T) {
	legalHold := true
	verifier := &fakeObjectRetentionVerifier{result: ObjectRetentionResult{
		Provider:      "s3",
		Bucket:        "evydence-test",
		Mode:          "compliance",
		RetentionDays: 90,
		LegalHold:     &legalHold,
		ObservedAt:    fixedNow(),
		Enforced:      true,
		Checks:        []domain.VerifyCheck{{Name: "s3_object_legal_hold", Result: "passed"}},
		Limitations:   []string{"Sample object legal hold checked only."},
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
	objectKey := "tenants/" + actor.TenantID + "/raw/sample.json"
	verifier.result.ObjectKey = objectKey
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "objects", ObjectPrefix: "tenants/" + actor.TenantID + "/raw/", ObjectKey: objectKey, RequireLegalHold: true, Mode: "compliance", RetentionDays: 90})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	verified, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("verify policy: %v", err)
	}
	if !verified.RequireLegalHold || len(verifier.requests) != 1 || !verifier.requests[0].RequireLegalHold || verifier.requests[0].ObjectKey != objectKey {
		t.Fatalf("verified=%#v requests=%#v", verified, verifier.requests)
	}
}

func TestObjectRetentionSampleObjectRequiresObservedLegalHoldState(t *testing.T) {
	verifier := &fakeObjectRetentionVerifier{result: ObjectRetentionResult{
		Provider:      "s3",
		Bucket:        "evydence-test",
		Mode:          "compliance",
		RetentionDays: 90,
		ObservedAt:    fixedNow(),
		Enforced:      true,
		Checks:        []domain.VerifyCheck{{Name: "s3_object_retention_until", Result: "passed"}},
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
	objectKey := "tenants/" + actor.TenantID + "/raw/sample.json"
	verifier.result.ObjectKey = objectKey
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "objects", ObjectPrefix: "tenants/" + actor.TenantID + "/raw/", ObjectKey: objectKey, Mode: "compliance", RetentionDays: 90})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	verified, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("verify policy: %v", err)
	}
	if verified.Status != "not_verified" || !hasVerifyCheck(verified.VerificationChecks, "provider_enforced_proof", "failed") {
		t.Fatalf("sample object without legal-hold state must not be current proof: %#v", verified)
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
	if verified.Status != "not_enforced" || !hasVerifyCheck(verified.VerificationChecks, "s3_object_lock_retention", "failed") {
		t.Fatalf("verified policy = %#v", verified)
	}
}

func TestObjectRetentionRequiresCompleteProviderObservation(t *testing.T) {
	verifier := &fakeObjectRetentionVerifier{result: ObjectRetentionResult{
		Provider:   "s3",
		ObservedAt: fixedNow(),
		Enforced:   true,
		Checks:     []domain.VerifyCheck{{Name: "s3_bucket_versioning", Result: "passed"}},
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
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "objects", Mode: "compliance", RetentionDays: 30})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	verified, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("verify policy: %v", err)
	}
	if verified.Status != "not_verified" || verified.VerificationExpiresAt != nil {
		t.Fatalf("incomplete provider observation must not be current proof: %#v", verified)
	}
	if !hasVerifyCheck(verified.VerificationChecks, "provider_enforced_proof", "failed") {
		t.Fatalf("incomplete provider observation checks = %#v", verified.VerificationChecks)
	}
}

func TestObjectRetentionProviderUnavailableIsRecordedWithoutLeakingError(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Retention: &fakeObjectRetentionVerifier{err: errors.New("s3 credential secret must not leak")}})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "objects", Mode: "compliance", RetentionDays: 30})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	verified, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("provider unavailability should produce a persisted non-positive result: %v", err)
	}
	if verified.Status != "not_verified" || !hasVerifyCheck(verified.VerificationChecks, "provider_observation", "error") {
		t.Fatalf("provider unavailable policy = %#v", verified)
	}
	if strings.Contains(strings.Join(verified.VerificationLimitations, "\n"), "credential secret") {
		t.Fatalf("provider error leaked into persisted limitation: %#v", verified.VerificationLimitations)
	}
}

func TestObjectRetentionStaleProofNoLongerCountsAsCurrent(t *testing.T) {
	now := fixedNow()
	verifier := &fakeObjectRetentionVerifier{result: ObjectRetentionResult{
		Provider:      "s3",
		Bucket:        "evydence-test",
		Mode:          "compliance",
		RetentionDays: 90,
		ObservedAt:    now,
		Enforced:      true,
		Checks:        []domain.VerifyCheck{{Name: "s3_bucket_versioning", Result: "passed"}},
	}}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: func() time.Time { return now }, Retention: verifier})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "objects", Mode: "compliance", RetentionDays: 30, MaxVerificationAgeHours: 1})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	verified, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil || verified.Status != "verified" || verified.VerificationExpiresAt == nil {
		t.Fatalf("fresh provider proof = %#v err=%v", verified, err)
	}
	now = now.Add(2 * time.Hour)
	report, err := ledger.SigningCustodyReviewReport(ctx, actor)
	if err != nil {
		t.Fatalf("custody report: %v", err)
	}
	if len(report.ObjectRetentionPolicies) != 1 || report.ObjectRetentionPolicies[0].Status != "stale" {
		t.Fatalf("stale retention policy was treated as current: %#v", report.ObjectRetentionPolicies)
	}
	if !hasVerifyCheck(report.Checks, "object_lock_proof_recorded", "failed") {
		t.Fatalf("stale retention proof counted as current: %#v", report.Checks)
	}
}

func TestObjectRetentionVerificationAgeInputIsBounded(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "default age", Mode: "governance", RetentionDays: 30})
	if err != nil || policy.MaxVerificationAgeHours != defaultRetentionVerificationAgeHours {
		t.Fatalf("default retention verification age = %#v err=%v", policy, err)
	}
	if _, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "invalid age", Mode: "governance", RetentionDays: 30, MaxVerificationAgeHours: maxRetentionVerificationAgeHours + 1}); !errors.Is(err, ErrValidation) {
		t.Fatalf("out-of-range verification age err=%v, want validation", err)
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
	ledger := newLedgerWithStore(t, Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store, ObjectStore: objects})
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
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api","purl":"pkg:oci/api"}]}`))
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
	restored := newLedgerWithStore(t, Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: restoredStore, ObjectStore: restoredObjects})

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
