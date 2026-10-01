package app

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var errVerificationTestFailure = errors.New("verification test failure")

func TestVerifySubjectAggregatesPolicyAndPersistsReceiptAtomically(t *testing.T) {
	state := newVerificationTestState()
	state.subject = SubjectReference{TenantID: "ten_1", Type: "evidence_item", ID: "ev_1", Resources: application.ResourceReferences{ProductID: "prod_1", ReleaseID: "rel_1"}}
	state.inspection = SubjectInspection{
		Profile: verificationdomain.VerificationProfile{ID: "evidence", RequiredChecks: []string{"canonical_hash"}},
		Checks:  []verificationdomain.VerifyCheck{{Name: "canonical_hash", Result: "passed"}},
	}
	service := newVerificationTestService(t, state)

	result, err := service.VerifySubject(context.Background(), verificationTestActor(), "evidence_item", "ev_1")
	if err != nil {
		t.Fatalf("verify subject: %v", err)
	}
	if result.ID != "vr_1" || result.Result.String() != "passed" || state.results[result.ID].SubjectID != "ev_1" {
		t.Fatalf("unexpected result: %#v persisted=%#v", result, state.results)
	}
	if len(state.audit) != 1 || len(state.outbox) != 1 || state.outbox[0].Kind != "verify_subject" || state.outbox[0].Payload["result_id"] != result.ID {
		t.Fatalf("transaction effects: audit=%#v outbox=%#v", state.audit, state.outbox)
	}
}

func TestVerifySubjectPersistsFailedReceiptAndReturnsFailure(t *testing.T) {
	state := newVerificationTestState()
	state.subject = SubjectReference{TenantID: "ten_1", Type: "release_bundle", ID: "rb_1", Resources: application.ResourceReferences{ReleaseID: "rel_1"}}
	state.inspection = SubjectInspection{
		Profile: verificationdomain.VerificationProfile{ID: "bundle", RequiredChecks: []string{"manifest_hash", "bundle_signature"}},
		Checks:  []verificationdomain.VerifyCheck{{Name: "manifest_hash", Result: "passed"}, {Name: "bundle_signature", Result: "failed"}},
	}
	service := newVerificationTestService(t, state)

	result, err := service.VerifySubject(context.Background(), verificationTestActor(), "release_bundle", "rb_1")
	if !errors.Is(err, ErrVerificationFailed) || result.Result.String() != "failed" || state.results[result.ID].Result.String() != "failed" {
		t.Fatalf("failed verification = %#v, %v persisted=%#v", result, err, state.results)
	}
}

func TestVerifySubjectAcceptsOnlyConservativeNotVerifiedOverride(t *testing.T) {
	state := newVerificationTestState()
	notVerified, _ := verificationdomain.ParseVerificationState(verificationdomain.VerificationStateNotVerified)
	state.subject = SubjectReference{TenantID: "ten_1", Type: "build_attestation", ID: "att_1", Resources: application.ResourceReferences{BuildID: "build_1"}}
	state.inspection = SubjectInspection{
		Profile:       verificationdomain.VerificationProfile{ID: "dsse", RequiredChecks: []string{"trusted_root"}},
		Checks:        []verificationdomain.VerifyCheck{{Name: "trusted_root", Result: verificationdomain.VerificationStateNotVerified}},
		StateOverride: notVerified,
	}
	service := newVerificationTestService(t, state)

	result, err := service.VerifySubject(context.Background(), verificationTestActor(), "build_attestation", "att_1")
	if err != nil || result.Result.String() != verificationdomain.VerificationStateNotVerified {
		t.Fatalf("not-verified result=%#v err=%v", result, err)
	}

	passed, _ := verificationdomain.ParseVerificationState(verificationdomain.VerificationStatePassed)
	state.inspection.StateOverride = passed
	if _, err := service.VerifySubject(context.Background(), verificationTestActor(), "build_attestation", "att_1"); !errors.Is(err, ErrValidation) {
		t.Fatalf("optimistic override error = %v", err)
	}
}

func TestVerifySubjectRejectsInspectorMismatchAndRollsBackAuditFailure(t *testing.T) {
	state := newVerificationTestState()
	state.subject = SubjectReference{TenantID: "ten_2", Type: "evidence_item", ID: "ev_1"}
	service := newVerificationTestService(t, state)
	if _, err := service.VerifySubject(context.Background(), verificationTestActor(), "evidence_item", "ev_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign subject error = %v", err)
	}

	state.subject = SubjectReference{TenantID: "ten_1", Type: "evidence_item", ID: "ev_1"}
	state.inspection = SubjectInspection{Profile: verificationdomain.VerificationProfile{ID: "evidence", RequiredChecks: []string{"canonical_hash"}}, Checks: []verificationdomain.VerifyCheck{{Name: "canonical_hash", Result: "passed"}}}
	state.auditErr = errVerificationTestFailure
	if _, err := service.VerifySubject(context.Background(), verificationTestActor(), "evidence_item", "ev_1"); !errors.Is(err, errVerificationTestFailure) {
		t.Fatalf("audit failure = %v", err)
	}
	if len(state.results) != 0 || len(state.outbox) != 0 {
		t.Fatalf("failed transaction published: results=%#v outbox=%#v", state.results, state.outbox)
	}
}

func TestPrepareAndCommitInitialSigningKeyOwnsBootstrapSigningState(t *testing.T) {
	state := newVerificationTestState()
	service := newVerificationTestService(t, state)

	prepared, err := service.PrepareInitialSigningKey(context.Background(), "ten_1")
	if err != nil {
		t.Fatalf("prepare initial signing key: %v", err)
	}
	if len(state.keys) != 0 || len(state.privateMaterial) != 0 {
		t.Fatalf("preparation published signing state: keys=%#v private=%#v", state.keys, state.privateMaterial)
	}
	if prepared.Key.TenantID != "ten_1" || prepared.Key.Version != 1 || prepared.Key.Provider != verificationdomain.SigningKeyDefaultProvider || len(prepared.PrivateMaterial) == 0 {
		t.Fatalf("prepared signing key = %#v", prepared)
	}
	if err := service.CommitInitialSigningKey(context.Background(), state, "ten_1", prepared); err != nil {
		t.Fatalf("commit initial signing key: %v", err)
	}
	if state.keys[prepared.Key.ID].TenantID != "ten_1" || !reflect.DeepEqual(state.privateMaterial[prepared.Key.ID], []byte("private-material")) {
		t.Fatalf("committed key=%#v private=%#v", state.keys, state.privateMaterial)
	}

	foreign := clonePreparedSigningKey(prepared)
	foreign.Key.TenantID = "ten_2"
	if err := service.CommitInitialSigningKey(context.Background(), state, "ten_1", foreign); !errors.Is(err, ErrValidation) {
		t.Fatalf("foreign initial signing key error = %v", err)
	}
}

func TestRotateSigningKeyRetiresActiveKeysAndDoesNotReturnPrivateMaterial(t *testing.T) {
	state := newVerificationTestState()
	active, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
	state.keys["sk_old"] = verificationdomain.SigningKey{ID: "sk_old", TenantID: "ten_1", Version: 2, Provider: verificationdomain.SigningKeyDefaultProvider, Status: active, CreatedAt: verificationTestNow().Add(-time.Hour)}
	service := newVerificationTestService(t, state)

	key, err := service.RotateSigningKey(context.Background(), verificationTestActor(), "scheduled rotation")
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	if key.ID != "sk_1" || key.Version != 3 || key.Status.String() != "active" {
		t.Fatalf("new key = %#v", key)
	}
	if state.keys["sk_old"].Status.String() != "retiring" || state.keys["sk_old"].ValidUntil == nil {
		t.Fatalf("old key not retired: %#v", state.keys["sk_old"])
	}
	if !reflect.DeepEqual(state.privateMaterial["sk_1"], []byte("private-material")) {
		t.Fatalf("private material was not transactionally persisted: %#v", state.privateMaterial)
	}
}

func TestRotateSigningKeyIgnoresExternalProviderVersionsAndRollsBackOnAuditFailure(t *testing.T) {
	state := newVerificationTestState()
	active, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
	state.keys["sk_local"] = verificationdomain.SigningKey{ID: "sk_local", TenantID: "ten_1", Provider: verificationdomain.SigningKeyDefaultProvider, Version: 0, Status: active}
	state.keys["sk_hsm"] = verificationdomain.SigningKey{ID: "sk_hsm", TenantID: "ten_1", Provider: "native_pkcs11_hsm", Version: 99, Status: active}
	service := newVerificationTestService(t, state)
	state.auditErr = errVerificationTestFailure
	if _, err := service.RotateSigningKey(context.Background(), verificationTestActor(), "scheduled rotation"); !errors.Is(err, errVerificationTestFailure) {
		t.Fatalf("audit failure = %v", err)
	}
	if state.keys["sk_local"].Status.String() != "active" || state.keys["sk_hsm"].Status.String() != "active" || len(state.privateMaterial) != 0 || len(state.audit) != 0 {
		t.Fatalf("failed rotation published state: keys=%#v private=%#v audit=%#v", state.keys, state.privateMaterial, state.audit)
	}
	state.auditErr = nil
	key, err := service.RotateSigningKey(context.Background(), verificationTestActor(), "scheduled rotation")
	if err != nil || key.Version != 2 || state.keys["sk_local"].Status.String() != "retiring" || state.keys["sk_hsm"].Status.String() != "active" {
		t.Fatalf("provider-safe rotation = %#v, error=%v, keys=%#v", key, err, state.keys)
	}
}

func TestRevokeSigningKeyDefaultsToOrdinaryRevocationAndRejectsInvalidPolicy(t *testing.T) {
	state := newVerificationTestState()
	active, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
	state.keys["sk_1"] = verificationdomain.SigningKey{ID: "sk_1", TenantID: "ten_1", Status: active}
	state.keys["foreign"] = verificationdomain.SigningKey{ID: "foreign", TenantID: "ten_2", Status: active}
	service := newVerificationTestService(t, state)
	if _, err := service.RevokeSigningKey(context.Background(), verificationTestActor(), "sk_1", SigningKeyRevocationInput{Reason: "incident", Semantics: verificationdomain.SigningKeyRevocationOrdinary, HistoricalValidityPolicy: verificationdomain.SigningKeyHistoricalValidityInvalidateAll}); !errors.Is(err, ErrValidation) {
		t.Fatalf("ordinary revocation with retroactive invalidation error = %v", err)
	}
	if _, err := service.RevokeSigningKey(context.Background(), verificationTestActor(), "foreign", SigningKeyRevocationInput{Reason: "incident"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign key error = %v", err)
	}
	key, err := service.RevokeSigningKey(context.Background(), verificationTestActor(), "sk_1", SigningKeyRevocationInput{Reason: " retired "})
	if err != nil || key.RevocationSemantics != verificationdomain.SigningKeyRevocationOrdinary || key.HistoricalValidityPolicy != verificationdomain.SigningKeyHistoricalValidityPreserve || key.CompromisedAt != nil || key.RevocationReason != "retired" {
		t.Fatalf("ordinary revocation = %#v, error=%v", key, err)
	}
	if _, err := service.RevokeSigningKey(context.Background(), verificationTestActor(), "sk_1", SigningKeyRevocationInput{Reason: "again"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate revocation error = %v", err)
	}
	if len(state.audit) != 1 || state.audit[0].EntryType != "signing_key.revoked" {
		t.Fatalf("revocation audit = %#v", state.audit)
	}
}

func TestRevokeSigningKeyAndCreateProviderValidateSecurityPolicy(t *testing.T) {
	state := newVerificationTestState()
	active, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
	state.keys["sk_1"] = verificationdomain.SigningKey{ID: "sk_1", TenantID: "ten_1", Provider: verificationdomain.SigningKeyDefaultProvider, Status: active, CreatedAt: verificationTestNow().Add(-time.Hour)}
	service := newVerificationTestService(t, state)

	revoked, err := service.RevokeSigningKey(context.Background(), verificationTestActor(), "sk_1", SigningKeyRevocationInput{Reason: "suspected exposure", Semantics: verificationdomain.SigningKeyRevocationCompromised, HistoricalValidityPolicy: verificationdomain.SigningKeyHistoricalValidityInvalidateFromCompromise})
	if err != nil || revoked.Status.String() != "revoked" || revoked.CompromisedAt == nil {
		t.Fatalf("revoke key = %#v, %v", revoked, err)
	}
	if _, err := service.CreateSigningProvider(context.Background(), verificationTestActor(), CreateSigningProviderInput{Name: "HSM", Type: "native_pkcs11_hsm", KeyRef: "pkcs11:token=signing?pin-value=secret", Encrypted: true}); !errors.Is(err, ErrValidation) {
		t.Fatalf("secret-bearing key ref error = %v", err)
	}
	provider, err := service.CreateSigningProvider(context.Background(), verificationTestActor(), CreateSigningProviderInput{Name: "HSM", Type: "native_pkcs11_hsm", KeyRef: "pkcs11:token=signing;object=release-key", Encrypted: true})
	if err != nil || provider.KeyRef == "" || state.providers[provider.ID].TenantID != "ten_1" {
		t.Fatalf("create provider = %#v, %v", provider, err)
	}
}

func TestCreateDSSETrustRootValidatesPolicyAndPersistsThroughVerification(t *testing.T) {
	state := newVerificationTestState()
	service := newVerificationTestService(t, state)
	input := CreateDSSETrustRootInput{
		Name: " release provenance ", KeyID: " builder-key ", Algorithm: "Ed25519",
		PublicKey:             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		AllowedPredicateTypes: []string{"https://slsa.dev/provenance/v1"},
		ExpectedBuilderIDs:    []string{"https://ci.example.test/builder"},
		RequiredClaims:        []string{"external_parameters", "builder_id"},
	}

	root, err := service.CreateDSSETrustRoot(context.Background(), verificationTestActor(), input)
	if err != nil {
		t.Fatalf("create DSSE trust root: %v", err)
	}
	if root.TenantID != "ten_1" || root.Name != "release provenance" || root.KeyID != "builder-key" || root.Status != "active" || !reflect.DeepEqual(root.RequiredClaims, []string{"builder_id", "external_parameters"}) {
		t.Fatalf("root = %#v", root)
	}
	if state.roots[root.ID].TenantID != "ten_1" || len(state.audit) != 1 || state.audit[0].EntryType != "dsse_trust_root.created" {
		t.Fatalf("persisted roots=%#v audit=%#v", state.roots, state.audit)
	}

	input.PublicKey = "not-a-public-key"
	if _, err := service.CreateDSSETrustRoot(context.Background(), verificationTestActor(), input); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid public key error = %v", err)
	}
}

func TestCreateDSSETrustRootRejectsUnsupportedOrDuplicateTrustPolicy(t *testing.T) {
	base := CreateDSSETrustRootInput{
		Name: "builder", KeyID: "builder-key", Algorithm: "Ed25519", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		AllowedPredicateTypes: []string{"https://slsa.dev/provenance/v1"}, ExpectedBuilderIDs: []string{"https://ci.example.test/builder"}, RequiredClaims: []string{"builder_id"},
	}
	for _, tt := range []struct {
		name   string
		mutate func(*CreateDSSETrustRootInput)
	}{
		{"unsupported algorithm", func(v *CreateDSSETrustRootInput) { v.Algorithm = "none" }},
		{"unsupported predicate", func(v *CreateDSSETrustRootInput) {
			v.AllowedPredicateTypes = []string{"https://untrusted.example/predicate"}
		}},
		{"duplicate predicate", func(v *CreateDSSETrustRootInput) {
			v.AllowedPredicateTypes = []string{"https://slsa.dev/provenance/v1", "https://slsa.dev/provenance/v1"}
		}},
		{"duplicate builder", func(v *CreateDSSETrustRootInput) { v.ExpectedBuilderIDs = []string{"builder", "builder"} }},
		{"blank builder", func(v *CreateDSSETrustRootInput) { v.ExpectedBuilderIDs = []string{""} }},
		{"unsupported required claim", func(v *CreateDSSETrustRootInput) { v.RequiredClaims = []string{"private_key"} }},
		{"duplicate required claim", func(v *CreateDSSETrustRootInput) { v.RequiredClaims = []string{"builder_id", "builder_id"} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := newVerificationTestState()
			service := newVerificationTestService(t, state)
			input := base
			tt.mutate(&input)
			if _, err := service.CreateDSSETrustRoot(context.Background(), verificationTestActor(), input); !errors.Is(err, ErrValidation) {
				t.Fatalf("trust root error = %v", err)
			}
			if len(state.roots) != 0 || len(state.audit) != 0 {
				t.Fatalf("invalid trust root persisted: roots=%#v audit=%#v", state.roots, state.audit)
			}
		})
	}
}

func TestVerifyCosignAuthorizesInspectsAndPersistsReceiptsAtomically(t *testing.T) {
	state := newVerificationTestState()
	state.cosignSubject = CosignSubject{
		TenantID: "ten_1", ArtifactID: "art_1", ContainerImageID: "img_1", ArtifactSignatureID: "asig_1",
		SubjectDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Resources:     application.ResourceReferences{ArtifactID: "art_1"},
	}
	state.cosignInspection = CosignInspection{
		Profile:             CosignFullProfile(CosignVerificationModeKeyless, state.cosignSubject.SubjectDigest),
		CertificateIdentity: "repo:owner/project", CertificateIssuer: "https://issuer.example.test",
		LibraryVersion: "sigstore-test", TrustRootVersion: "root-v1",
	}
	for _, name := range state.cosignInspection.Profile.RequiredChecks {
		state.cosignInspection.Checks = append(state.cosignInspection.Checks, verificationdomain.VerifyCheck{Name: name, Result: "passed"})
	}
	service := newVerificationTestService(t, state)

	record, err := service.VerifyCosign(context.Background(), verificationTestActor(), VerifyCosignInput{
		ArtifactSignatureID: "asig_1", ExpectedIdentity: "repo:owner/project", ExpectedIssuer: "https://issuer.example.test",
		Mode: CosignVerificationModeKeyless, Offline: true,
	})
	if err != nil {
		t.Fatalf("verify cosign: %v", err)
	}
	if record.ID == "" || record.TenantID != "ten_1" || record.ArtifactSignatureID != "asig_1" || record.Result != "passed" || record.Profile.ID != verificationdomain.VerificationProfileCosignFull || len(record.Checks) != 7 {
		t.Fatalf("record = %#v", record)
	}
	if state.cosignRecords[record.ID].ID != record.ID || state.results[record.ID].SubjectID != "asig_1" || len(state.audit) != 1 {
		t.Fatalf("cosign=%#v results=%#v audit=%#v", state.cosignRecords, state.results, state.audit)
	}

	state.cosignInspection.Outcome = CosignOutcomeUnavailable
	state.cosignInspection.Checks = []verificationdomain.VerifyCheck{{Name: "cryptographic_signature", Result: "failed"}}
	if unavailable, err := service.VerifyCosign(context.Background(), verificationTestActor(), VerifyCosignInput{ArtifactSignatureID: "asig_1", ExpectedIdentity: "repo:owner/project", ExpectedIssuer: "https://issuer.example.test", Mode: CosignVerificationModeKeyless, Offline: true}); !errors.Is(err, ErrFullVerificationUnavailable) || unavailable.ID == "" || state.cosignRecords[unavailable.ID].ID == "" {
		t.Fatalf("unavailable record=%#v err=%v persisted=%#v", unavailable, err, state.cosignRecords)
	}
}

func TestVerifyCosignRejectsUnsafeModeAndInspectorResult(t *testing.T) {
	base := CosignSubject{TenantID: "ten_1", ArtifactID: "art_1", ArtifactSignatureID: "asig_1", SubjectDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	for _, tt := range []struct {
		name       string
		input      VerifyCosignInput
		inspection CosignInspection
	}{
		{"online verification", VerifyCosignInput{ArtifactSignatureID: "asig_1", Mode: CosignVerificationModeKey, Offline: false}, CosignInspection{}},
		{"keyless without identity", VerifyCosignInput{ArtifactSignatureID: "asig_1", Mode: CosignVerificationModeKeyless, Offline: true}, CosignInspection{}},
		{"key mode with keyless identity", VerifyCosignInput{ArtifactSignatureID: "asig_1", Mode: CosignVerificationModeKey, ExpectedIdentity: "unexpected", Offline: true}, CosignInspection{}},
		{"invalid inspector outcome", VerifyCosignInput{ArtifactSignatureID: "asig_1", Mode: CosignVerificationModeKey, Offline: true}, CosignInspection{Profile: verificationdomain.VerificationProfile{ID: "cosign", RequiredChecks: []string{"signature"}}, Checks: []verificationdomain.VerifyCheck{{Name: "signature", Result: "passed"}}, Outcome: "invented"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := newVerificationTestState()
			state.cosignSubject, state.cosignInspection = base, tt.inspection
			service := newVerificationTestService(t, state)
			if _, err := service.VerifyCosign(context.Background(), verificationTestActor(), tt.input); !errors.Is(err, ErrValidation) {
				t.Fatalf("cosign verification error = %v", err)
			}
			if len(state.cosignRecords) != 0 || len(state.results) != 0 || len(state.audit) != 0 {
				t.Fatalf("invalid cosign input persisted: records=%#v results=%#v audit=%#v", state.cosignRecords, state.results, state.audit)
			}
		})
	}
}

func TestVerifyCosignKeyModePersistsFailedReceiptWithoutTrustClaim(t *testing.T) {
	state := newVerificationTestState()
	state.cosignSubject = CosignSubject{TenantID: "ten_1", ArtifactID: "art_1", ArtifactSignatureID: "asig_1", SubjectDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	state.cosignInspection = CosignInspection{Profile: CosignFullProfile(CosignVerificationModeKey, state.cosignSubject.SubjectDigest), Checks: []verificationdomain.VerifyCheck{{Name: "cryptographic_signature", Result: "failed"}}, Outcome: CosignOutcomeVerificationFailed}
	service := newVerificationTestService(t, state)
	record, err := service.VerifyCosign(context.Background(), verificationTestActor(), VerifyCosignInput{ArtifactSignatureID: "asig_1", Mode: CosignVerificationModeKey, Offline: true})
	if !errors.Is(err, ErrVerificationFailed) || record.Result != "failed" || state.cosignRecords[record.ID].Result != "failed" || state.results[record.ID].Result.String() != "failed" {
		t.Fatalf("failed key-mode receipt = %#v, error=%v, records=%#v, results=%#v", record, err, state.cosignRecords, state.results)
	}
}

func TestCreateMerkleBatchAndTransparencyCheckpointPersistAtomically(t *testing.T) {
	state := newVerificationTestState()
	state.auditChain = []AuditChainLeaf{{Sequence: 1, EntryHash: "sha256:one"}, {Sequence: 2, EntryHash: "sha256:two"}}
	service := newVerificationTestService(t, state)

	batch, err := service.CreateMerkleBatch(context.Background(), verificationTestActor(), CreateMerkleBatchInput{})
	if err != nil {
		t.Fatalf("create Merkle batch: %v", err)
	}
	if batch.FromSequence != 1 || batch.ToSequence != 2 || batch.EntryCount != 2 || batch.RootHash == "" || len(batch.SignatureRefs) != 1 {
		t.Fatalf("batch = %#v", batch)
	}
	if state.merkleBatches[batch.ID].ID == "" || state.signatures[batch.SignatureRefs[0]].SubjectID != batch.ID || len(state.audit) != 1 {
		t.Fatalf("batches=%#v signatures=%#v audit=%#v", state.merkleBatches, state.signatures, state.audit)
	}

	checkpoint, err := service.CreateTransparencyCheckpoint(context.Background(), verificationTestActor(), CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "rfc3161", ExternalID: "checkpoint-1"})
	if err != nil {
		t.Fatalf("create transparency checkpoint: %v", err)
	}
	if checkpoint.BatchID != batch.ID || checkpoint.TimestampHash == "" || checkpoint.State != "recorded" || state.checkpoints[checkpoint.ID].ID == "" || len(state.audit) != 2 {
		t.Fatalf("checkpoint=%#v persisted=%#v audit=%#v", checkpoint, state.checkpoints, state.audit)
	}
}

func TestCreateMerkleBatchRejectsIncompleteAuditChainAndRange(t *testing.T) {
	for _, tt := range []struct {
		name   string
		leaves []AuditChainLeaf
		range_ CreateMerkleBatchInput
	}{
		{"empty chain", nil, CreateMerkleBatchInput{}},
		{"missing sequence", []AuditChainLeaf{{Sequence: 1, EntryHash: "sha256:one"}, {Sequence: 3, EntryHash: "sha256:three"}}, CreateMerkleBatchInput{}},
		{"empty hash", []AuditChainLeaf{{Sequence: 1, EntryHash: " "}}, CreateMerkleBatchInput{}},
		{"inverted range", []AuditChainLeaf{{Sequence: 1, EntryHash: "sha256:one"}}, CreateMerkleBatchInput{FromSequence: 2, ToSequence: 1}},
		{"range exceeds committed chain", []AuditChainLeaf{{Sequence: 1, EntryHash: "sha256:one"}}, CreateMerkleBatchInput{FromSequence: 1, ToSequence: 2}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := newVerificationTestState()
			state.auditChain = tt.leaves
			service := newVerificationTestService(t, state)
			if _, err := service.CreateMerkleBatch(context.Background(), verificationTestActor(), tt.range_); !errors.Is(err, ErrValidation) {
				t.Fatalf("Merkle batch error = %v", err)
			}
			if len(state.merkleBatches) != 0 || len(state.signatures) != 0 || len(state.audit) != 0 {
				t.Fatalf("invalid chain persisted effects: batches=%#v signatures=%#v audit=%#v", state.merkleBatches, state.signatures, state.audit)
			}
		})
	}
}

func TestCreateMerkleBatchCommitsSignerCreatedKeyAtomically(t *testing.T) {
	state := newVerificationTestState()
	state.auditChain = []AuditChainLeaf{{Sequence: 1, EntryHash: "sha256:one"}}
	status, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
	prepared := PreparedSigningKey{Key: verificationdomain.SigningKey{
		ID: "sk_1", TenantID: "ten_1", KID: "kid-1", Version: 1, Provider: verificationdomain.SigningKeyDefaultProvider,
		Algorithm: "Ed25519", Status: status, PublicKey: "public", PublicKeyFingerprint: "sha256:abc",
		ValidFrom: verificationTestNow(), CreatedAt: verificationTestNow(),
	}, PrivateMaterial: []byte("private-material")}
	state.signingKey = &prepared
	service := newVerificationTestService(t, state)
	batch, err := service.CreateMerkleBatch(context.Background(), verificationTestActor(), CreateMerkleBatchInput{})
	if err != nil || batch.ID == "" || state.keys["sk_1"].ID != "sk_1" || !reflect.DeepEqual(state.privateMaterial["sk_1"], []byte("private-material")) {
		t.Fatalf("signer-created key/batch = %#v, key=%#v, private=%#v, err=%v", batch, state.keys, state.privateMaterial, err)
	}
	if len(state.audit) != 1 || len(state.signatures) != 1 {
		t.Fatalf("transaction effects = audit=%#v signatures=%#v", state.audit, state.signatures)
	}
	state.auditErr = errVerificationTestFailure
	if _, err := service.CreateMerkleBatch(context.Background(), verificationTestActor(), CreateMerkleBatchInput{}); !errors.Is(err, errVerificationTestFailure) {
		t.Fatalf("audit failure = %v", err)
	}
	if len(state.merkleBatches) != 1 || len(state.audit) != 1 {
		t.Fatalf("audit failure published batch or audit: batches=%#v audit=%#v", state.merkleBatches, state.audit)
	}
}

func TestTransparencyCheckpointRejectsMissingAndForeignBatches(t *testing.T) {
	state := newVerificationTestState()
	state.merkleBatches["foreign"] = verificationdomain.MerkleBatch{ID: "foreign", TenantID: "ten_2", RootHash: "sha256:root"}
	state.merkleBatches["empty_root"] = verificationdomain.MerkleBatch{ID: "empty_root", TenantID: "ten_1"}
	service := newVerificationTestService(t, state)
	for _, tt := range []struct {
		name  string
		input CreateTransparencyCheckpointInput
		want  error
	}{
		{"missing provider", CreateTransparencyCheckpointInput{BatchID: "foreign", ExternalID: "external"}, ErrValidation},
		{"missing external coordinate", CreateTransparencyCheckpointInput{BatchID: "foreign", Provider: "rfc3161"}, ErrValidation},
		{"foreign batch", CreateTransparencyCheckpointInput{BatchID: "foreign", Provider: "rfc3161", ExternalID: "external"}, ErrNotFound},
		{"unknown batch", CreateTransparencyCheckpointInput{BatchID: "missing", Provider: "rfc3161", ExternalID: "external"}, ErrNotFound},
		{"empty committed root", CreateTransparencyCheckpointInput{BatchID: "empty_root", Provider: "rfc3161", ExternalID: "external"}, ErrNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := service.CreateTransparencyCheckpoint(context.Background(), verificationTestActor(), tt.input); !errors.Is(err, tt.want) {
				t.Fatalf("checkpoint error = %v, want %v", err, tt.want)
			}
		})
	}
	if len(state.checkpoints) != 0 || len(state.audit) != 0 {
		t.Fatalf("invalid checkpoint persisted: checkpoints=%#v audit=%#v", state.checkpoints, state.audit)
	}
}

func TestRetentionCustodyAndBackupWorkflowsUseFocusedSnapshotsAndRepositories(t *testing.T) {
	state := newVerificationTestState()
	legalHold := true
	state.retentionConfigured = true
	state.retentionObservation = RetentionObservation{
		Provider: "s3", Bucket: "evidence", ObjectKey: "tenants/ten_1/raw/sample.json", Mode: "compliance",
		RetentionDays: 90, Enforced: true, LegalHold: &legalHold, ObservedAt: verificationTestNow(),
		Checks: []verificationdomain.VerifyCheck{{Name: "provider_lock", Result: "passed"}},
	}
	state.backupSnapshot = BackupSnapshot{
		TenantID: "ten_1", StateHash: "sha256:backup", ResourceCounts: map[string]int{"evidence": 3},
		ConsistencyChecks: []verificationdomain.VerifyCheck{{Name: "audit_chain", Result: "passed"}},
	}
	service := newVerificationTestService(t, state)

	policy, err := service.CreateObjectRetentionPolicy(context.Background(), verificationTestActor(), CreateObjectRetentionPolicyInput{
		Name: " evidence lock ", ObjectKey: "tenants/ten_1/raw/sample.json", Mode: "compliance", RetentionDays: 90, RequireLegalHold: true,
	})
	if err != nil {
		t.Fatalf("create retention policy: %v", err)
	}
	if policy.ObjectPrefix != "tenants/ten_1/" || policy.Status != "configured" || state.retentionPolicies[policy.ID].ID == "" {
		t.Fatalf("policy=%#v persisted=%#v", policy, state.retentionPolicies)
	}
	verified, err := service.VerifyObjectRetentionPolicy(context.Background(), verificationTestActor(), policy.ID)
	if err != nil {
		t.Fatalf("verify retention policy: %v", err)
	}
	if verified.Status != "verified" || verified.VerificationHash == "" || verified.VerificationExpiresAt == nil || state.retentionPolicies[policy.ID].Status != "verified" {
		t.Fatalf("verified policy=%#v persisted=%#v", verified, state.retentionPolicies[policy.ID])
	}

	state.providers["sp_1"] = verificationdomain.SigningProvider{ID: "sp_1", TenantID: "ten_1", Type: "native_pkcs11_hsm"}
	report, err := service.SigningCustodyReviewReport(context.Background(), verificationTestActor())
	if err != nil || report.TenantID != "ten_1" || len(report.SigningProviders) != 1 || len(report.ObjectRetentionPolicies) != 1 {
		t.Fatalf("custody report=%#v err=%v", report, err)
	}

	manifest, err := service.GenerateBackupManifest(context.Background(), verificationTestActor())
	if err != nil {
		t.Fatalf("generate backup manifest: %v", err)
	}
	if manifest.StateHash != "sha256:backup" || state.backupManifests[manifest.ID].ID == "" || len(state.audit) != 3 {
		t.Fatalf("manifest=%#v persisted=%#v audit=%#v", manifest, state.backupManifests, state.audit)
	}
}

func TestCreateRetentionPolicyRejectsCrossTenantObjectScopeAndUnsafeSettings(t *testing.T) {
	base := CreateObjectRetentionPolicyInput{Name: "evidence", ObjectPrefix: "tenants/ten_1/", ObjectKey: "tenants/ten_1/raw/item.json", Mode: "compliance", RetentionDays: 30, RequireLegalHold: true}
	for _, tt := range []struct {
		name   string
		mutate func(*CreateObjectRetentionPolicyInput)
	}{
		{"foreign prefix", func(v *CreateObjectRetentionPolicyInput) { v.ObjectPrefix = "tenants/ten_2/" }},
		{"foreign object key", func(v *CreateObjectRetentionPolicyInput) { v.ObjectKey = "tenants/ten_2/raw/item.json" }},
		{"object outside prefix", func(v *CreateObjectRetentionPolicyInput) { v.ObjectPrefix = "tenants/ten_1/evidence/" }},
		{"legal hold without object", func(v *CreateObjectRetentionPolicyInput) { v.ObjectKey = "" }},
		{"zero retention", func(v *CreateObjectRetentionPolicyInput) { v.RetentionDays = 0 }},
		{"invalid mode", func(v *CreateObjectRetentionPolicyInput) { v.Mode = "disabled" }},
		{"excessive verification age", func(v *CreateObjectRetentionPolicyInput) {
			v.MaxVerificationAgeHours = maxRetentionVerificationAgeHours + 1
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := newVerificationTestState()
			service := newVerificationTestService(t, state)
			input := base
			tt.mutate(&input)
			if _, err := service.CreateObjectRetentionPolicy(context.Background(), verificationTestActor(), input); !errors.Is(err, ErrValidation) {
				t.Fatalf("retention policy error = %v", err)
			}
			if len(state.retentionPolicies) != 0 || len(state.audit) != 0 {
				t.Fatalf("invalid policy persisted: policies=%#v audit=%#v", state.retentionPolicies, state.audit)
			}
		})
	}
}

func TestSigningCustodyReportDoesNotTreatStaleRetentionAsVerified(t *testing.T) {
	state := newVerificationTestState()
	status := "verified"
	observed := verificationTestNow().Add(-48 * time.Hour)
	expired := verificationTestNow().Add(-24 * time.Hour)
	state.retentionPolicies["orp_1"] = verificationdomain.ObjectRetentionPolicy{
		ID: "orp_1", TenantID: "ten_1", Status: status, VerificationHash: "sha256:old",
		VerificationObservedAt: &observed, VerificationExpiresAt: &expired,
	}
	service := newVerificationTestService(t, state)
	report, err := service.SigningCustodyReviewReport(context.Background(), verificationTestActor())
	if err != nil || len(report.ObjectRetentionPolicies) != 1 || report.ObjectRetentionPolicies[0].Status == "verified" || report.Checks[2].Result == "passed" {
		t.Fatalf("stale retention was trusted: report=%#v, error=%v", report, err)
	}
	if state.retentionPolicies["orp_1"].Status != status || len(state.audit) != 0 {
		t.Fatalf("read-only custody report modified history: policies=%#v audit=%#v", state.retentionPolicies, state.audit)
	}
}

func TestGenerateBackupManifestRejectsForeignSnapshotAndRollsBackAuditFailure(t *testing.T) {
	state := newVerificationTestState()
	service := newVerificationTestService(t, state)
	state.backupSnapshot = BackupSnapshot{TenantID: "ten_2", StateHash: "sha256:foreign"}
	if _, err := service.GenerateBackupManifest(context.Background(), verificationTestActor()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign backup snapshot error = %v", err)
	}
	state.backupSnapshot = BackupSnapshot{TenantID: "ten_1", StateHash: " "}
	if _, err := service.GenerateBackupManifest(context.Background(), verificationTestActor()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty state hash error = %v", err)
	}
	state.backupSnapshot = BackupSnapshot{TenantID: "ten_1", StateHash: "sha256:backup", ResourceCounts: map[string]int{"evidence": 2}}
	state.auditErr = errVerificationTestFailure
	if _, err := service.GenerateBackupManifest(context.Background(), verificationTestActor()); !errors.Is(err, errVerificationTestFailure) {
		t.Fatalf("audit failure = %v", err)
	}
	if len(state.backupManifests) != 0 || len(state.audit) != 0 {
		t.Fatalf("failed backup manifest persisted: manifests=%#v audit=%#v", state.backupManifests, state.audit)
	}
}

func TestRetentionVerificationDoesNotPersistCancellationAsProviderFailure(t *testing.T) {
	state := newVerificationTestState()
	state.retentionPolicies["orp_1"] = verificationdomain.ObjectRetentionPolicy{
		ID: "orp_1", TenantID: "ten_1", Name: "objects", ObjectPrefix: "tenants/ten_1/", Mode: "governance",
		RetentionDays: 30, MaxVerificationAgeHours: 24, Status: "configured",
		SchemaVersion: verificationdomain.ObjectRetentionPolicyVersion, CreatedAt: verificationTestNow(),
	}
	state.retentionConfigured = true
	state.retentionErr = context.Canceled
	service := newVerificationTestService(t, state)

	if _, err := service.VerifyObjectRetentionPolicy(context.Background(), verificationTestActor(), "orp_1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("verification error=%v, want cancellation", err)
	}
	if state.retentionPolicies["orp_1"].Status != "configured" || len(state.audit) != 0 {
		t.Fatalf("cancellation persisted provider failure: policy=%#v audit=%#v", state.retentionPolicies["orp_1"], state.audit)
	}
}

func TestUnavailableRetentionProviderRevokesPriorPositiveObservation(t *testing.T) {
	state := newVerificationTestState()
	observedAt := verificationTestNow().Add(-time.Hour)
	expiresAt := verificationTestNow().Add(time.Hour)
	state.retentionPolicies["orp_1"] = verificationdomain.ObjectRetentionPolicy{
		ID: "orp_1", TenantID: "ten_1", Name: "objects", ObjectPrefix: "tenants/ten_1/", Mode: "governance",
		RetentionDays: 30, MaxVerificationAgeHours: 24, Status: "verified",
		VerificationProvider: "s3", VerificationBucket: "evidence", VerificationObservedAt: &observedAt,
		VerificationExpiresAt: &expiresAt, VerificationHash: "sha256:prior",
		SchemaVersion: verificationdomain.ObjectRetentionPolicyVersion, CreatedAt: verificationTestNow().Add(-2 * time.Hour),
	}
	state.retentionConfigured = true
	state.retentionErr = errors.New("provider-internal-secret")
	service := newVerificationTestService(t, state)

	policy, err := service.VerifyObjectRetentionPolicy(context.Background(), verificationTestActor(), "orp_1")
	if err != nil {
		t.Fatalf("unavailable provider should persist a conservative result: %v", err)
	}
	if policy.Status != "not_verified" || policy.VerificationProvider != "" || policy.VerificationBucket != "" || policy.VerificationObservedAt != nil || policy.VerificationExpiresAt != nil || policy.VerificationHash == "sha256:prior" {
		t.Fatalf("stale provider proof remained trusted: %#v", policy)
	}
	if len(policy.VerificationChecks) < 4 || policy.VerificationChecks[2].Name != "provider_observation" || policy.VerificationChecks[2].Result != "error" || len(state.audit) != 1 || state.audit[0].EntryType != "object_retention_policy.verification_failed" {
		t.Fatalf("conservative verification result/audit missing: policy=%#v audit=%#v", policy, state.audit)
	}
	if reflect.DeepEqual(state.retentionPolicies["orp_1"], verificationdomain.ObjectRetentionPolicy{}) || state.retentionPolicies["orp_1"].Status != policy.Status {
		t.Fatalf("conservative result not persisted: %#v", state.retentionPolicies["orp_1"])
	}
}

func TestListSigningKeysSortsTenantKeysAndRejectsLeakyReader(t *testing.T) {
	state := newVerificationTestState()
	status, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
	state.keys["sk_2"] = verificationdomain.SigningKey{ID: "sk_2", TenantID: "ten_1", Status: status, CreatedAt: verificationTestNow()}
	state.keys["sk_1"] = verificationdomain.SigningKey{ID: "sk_1", TenantID: "ten_1", Status: status, CreatedAt: verificationTestNow().Add(-time.Hour)}
	state.keys["sk_foreign"] = verificationdomain.SigningKey{ID: "sk_foreign", TenantID: "ten_2", Status: status}
	service := newVerificationTestService(t, state)

	keys, err := service.ListSigningKeys(context.Background(), verificationTestActor())
	if err != nil || len(keys) != 2 || keys[0].ID != "sk_1" || keys[1].ID != "sk_2" {
		t.Fatalf("tenant key list = %#v, %v", keys, err)
	}
	state.leakSigningKeys = true
	if _, err := service.ListSigningKeys(context.Background(), verificationTestActor()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("leaky reader error = %v, want not found", err)
	}
}

func newVerificationTestService(t *testing.T, state *verificationTestState) *Service {
	t.Helper()
	service, err := NewService(Config{
		Subjects: state, Inspector: state, CosignSubjects: state, CosignInspector: state,
		Integrity: state, Signer: state, CanonicalHasher: state, RetentionVerifier: state,
		Reader: state, Transactions: state, KeyFactory: verificationTestKeyFactory{},
		Authorizer: allowVerificationAuthorizer{}, Clock: application.ClockFunc(verificationTestNow), IDs: application.IDGeneratorFunc(state.nextID),
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func verificationTestNow() time.Time { return time.Date(2026, 9, 4, 14, 0, 0, 0, time.UTC) }

func verificationTestActor() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", KeyID: "key_1", Scopes: []string{"verify:read", "keys:admin"}}
}

type allowVerificationAuthorizer struct{}

func (allowVerificationAuthorizer) Authorize(context.Context, identitydomain.Actor, application.AuthorizationRequest) error {
	return nil
}

type verificationTestKeyFactory struct{}

func (verificationTestKeyFactory) GenerateSigningKey(_ context.Context, tenantID, provider string, version int, now time.Time) (PreparedSigningKey, error) {
	status, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
	return PreparedSigningKey{Key: verificationdomain.SigningKey{ID: "sk_1", TenantID: tenantID, KID: "kid-1", Version: version, Provider: provider, Algorithm: "Ed25519", Status: status, PublicKey: "public", PublicKeyFingerprint: "sha256:abc", ValidFrom: now, CreatedAt: now, HistoricalValidityPolicy: verificationdomain.SigningKeyHistoricalValidityPreserve}, PrivateMaterial: []byte("private-material")}, nil
}

type verificationTestState struct {
	subject              SubjectReference
	inspection           SubjectInspection
	results              map[string]verificationdomain.VerificationResult
	keys                 map[string]verificationdomain.SigningKey
	leakSigningKeys      bool
	privateMaterial      map[string][]byte
	providers            map[string]verificationdomain.SigningProvider
	roots                map[string]verificationdomain.DSSETrustRoot
	cosignSubject        CosignSubject
	cosignInspection     CosignInspection
	cosignRecords        map[string]verificationdomain.CosignVerification
	auditChain           []AuditChainLeaf
	merkleBatches        map[string]verificationdomain.MerkleBatch
	signingKey           *PreparedSigningKey
	checkpoints          map[string]verificationdomain.TransparencyCheckpoint
	signatures           map[string]verificationdomain.Signature
	retentionPolicies    map[string]verificationdomain.ObjectRetentionPolicy
	retentionConfigured  bool
	retentionObservation RetentionObservation
	retentionErr         error
	backupSnapshot       BackupSnapshot
	backupManifests      map[string]verificationdomain.BackupManifest
	audit                []application.AuditEvent
	outbox               []application.OutboxEvent
	auditErr             error
	ids                  map[string]int
}

func newVerificationTestState() *verificationTestState {
	return &verificationTestState{results: map[string]verificationdomain.VerificationResult{}, keys: map[string]verificationdomain.SigningKey{}, privateMaterial: map[string][]byte{}, providers: map[string]verificationdomain.SigningProvider{}, roots: map[string]verificationdomain.DSSETrustRoot{}, cosignRecords: map[string]verificationdomain.CosignVerification{}, merkleBatches: map[string]verificationdomain.MerkleBatch{}, checkpoints: map[string]verificationdomain.TransparencyCheckpoint{}, signatures: map[string]verificationdomain.Signature{}, retentionPolicies: map[string]verificationdomain.ObjectRetentionPolicy{}, backupManifests: map[string]verificationdomain.BackupManifest{}, ids: map[string]int{}}
}

func (s *verificationTestState) nextID(prefix string) string {
	s.ids[prefix]++
	return prefix + "_" + strconv.Itoa(s.ids[prefix])
}

func (s *verificationTestState) ResolveVerificationSubject(context.Context, string, string, string) (SubjectReference, error) {
	return s.subject, nil
}
func (s *verificationTestState) InspectSubject(context.Context, SubjectReference) (SubjectInspection, error) {
	return cloneSubjectInspection(s.inspection), nil
}
func (s *verificationTestState) ListSigningKeys(_ context.Context, tenantID string) ([]verificationdomain.SigningKey, error) {
	result := []verificationdomain.SigningKey{}
	for _, value := range s.keys {
		if value.TenantID == tenantID || s.leakSigningKeys {
			result = append(result, cloneSigningKey(value))
		}
	}
	return result, nil
}
func (s *verificationTestState) Execute(ctx context.Context, command TransactionCommand) error {
	working := newVerificationTestState()
	working.subject, working.inspection, working.auditErr, working.ids = s.subject, cloneSubjectInspection(s.inspection), s.auditErr, s.ids
	working.cosignSubject, working.cosignInspection = s.cosignSubject, cloneCosignInspection(s.cosignInspection)
	working.auditChain = append([]AuditChainLeaf(nil), s.auditChain...)
	working.retentionConfigured, working.retentionObservation, working.retentionErr = s.retentionConfigured, cloneRetentionObservation(s.retentionObservation), s.retentionErr
	working.backupSnapshot = cloneBackupSnapshot(s.backupSnapshot)
	for key, value := range s.results {
		working.results[key] = cloneVerificationResult(value)
	}
	for key, value := range s.keys {
		working.keys[key] = cloneSigningKey(value)
	}
	for key, value := range s.privateMaterial {
		working.privateMaterial[key] = append([]byte(nil), value...)
	}
	for key, value := range s.providers {
		working.providers[key] = value
	}
	for key, value := range s.roots {
		working.roots[key] = cloneDSSETrustRoot(value)
	}
	for key, value := range s.cosignRecords {
		working.cosignRecords[key] = cloneCosignVerification(value)
	}
	for key, value := range s.merkleBatches {
		working.merkleBatches[key] = cloneMerkleBatch(value)
	}
	for key, value := range s.checkpoints {
		working.checkpoints[key] = value
	}
	for key, value := range s.signatures {
		working.signatures[key] = value
	}
	for key, value := range s.retentionPolicies {
		working.retentionPolicies[key] = cloneObjectRetentionPolicy(value)
	}
	for key, value := range s.backupManifests {
		working.backupManifests[key] = cloneBackupManifest(value)
	}
	working.audit = append([]application.AuditEvent(nil), s.audit...)
	working.outbox = append([]application.OutboxEvent(nil), s.outbox...)
	if err := command(ctx, verificationTestTransaction{state: working}); err != nil {
		return err
	}
	s.results, s.keys, s.privateMaterial, s.providers, s.roots, s.cosignRecords, s.merkleBatches, s.checkpoints, s.signatures, s.retentionPolicies, s.backupManifests, s.audit, s.outbox = working.results, working.keys, working.privateMaterial, working.providers, working.roots, working.cosignRecords, working.merkleBatches, working.checkpoints, working.signatures, working.retentionPolicies, working.backupManifests, working.audit, working.outbox
	return nil
}
func (s *verificationTestState) InsertVerificationResult(_ context.Context, value verificationdomain.VerificationResult) error {
	s.results[value.ID] = cloneVerificationResult(value)
	return nil
}
func (s *verificationTestState) UpdateSigningKey(_ context.Context, value verificationdomain.SigningKey, _ string) error {
	s.keys[value.ID] = cloneSigningKey(value)
	return nil
}
func (s *verificationTestState) InsertSigningKey(_ context.Context, value PreparedSigningKey) error {
	s.keys[value.Key.ID] = cloneSigningKey(value.Key)
	s.privateMaterial[value.Key.ID] = append([]byte(nil), value.PrivateMaterial...)
	return nil
}
func (s *verificationTestState) GetSigningKeyForUpdate(_ context.Context, tenantID, id string) (verificationdomain.SigningKey, error) {
	value, ok := s.keys[id]
	if !ok || value.TenantID != tenantID {
		return verificationdomain.SigningKey{}, ErrNotFound
	}
	return cloneSigningKey(value), nil
}
func (s *verificationTestState) InsertSigningProvider(_ context.Context, value verificationdomain.SigningProvider) error {
	s.providers[value.ID] = value
	return nil
}
func (s *verificationTestState) InsertDSSETrustRoot(_ context.Context, value verificationdomain.DSSETrustRoot) error {
	s.roots[value.ID] = cloneDSSETrustRoot(value)
	return nil
}
func (s *verificationTestState) ResolveCosignSubject(context.Context, string, string) (CosignSubject, error) {
	return s.cosignSubject, nil
}
func (s *verificationTestState) InspectCosign(context.Context, CosignSubject, VerifyCosignInput) (CosignInspection, error) {
	return cloneCosignInspection(s.cosignInspection), nil
}
func (s *verificationTestState) InsertCosignVerification(_ context.Context, value verificationdomain.CosignVerification) error {
	s.cosignRecords[value.ID] = cloneCosignVerification(value)
	return nil
}
func (s *verificationTestState) ReadAuditChain(_ context.Context, _ string) ([]AuditChainLeaf, error) {
	return append([]AuditChainLeaf(nil), s.auditChain...), nil
}
func (s *verificationTestState) ReadMerkleBatch(_ context.Context, tenantID, id string) (verificationdomain.MerkleBatch, error) {
	value, ok := s.merkleBatches[id]
	if !ok || value.TenantID != tenantID {
		return verificationdomain.MerkleBatch{}, ErrNotFound
	}
	return cloneMerkleBatch(value), nil
}
func (s *verificationTestState) Sign(_ context.Context, request SigningRequest) (SigningResult, error) {
	return SigningResult{Signature: verificationdomain.Signature{ID: "sig_1", TenantID: request.TenantID, SubjectType: request.SubjectType, SubjectID: request.SubjectID, KeyID: "sk_1", Algorithm: "Ed25519", Value: "signature", CreatedAt: request.CreatedAt}, NewKey: s.signingKey}, nil
}
func (s *verificationTestState) Hash(any) (string, error) { return "sha256:checkpoint", nil }
func (s *verificationTestState) InsertSignature(_ context.Context, value verificationdomain.Signature) error {
	s.signatures[value.ID] = value
	return nil
}
func (s *verificationTestState) InsertMerkleBatch(_ context.Context, value verificationdomain.MerkleBatch) error {
	s.merkleBatches[value.ID] = cloneMerkleBatch(value)
	return nil
}
func (s *verificationTestState) InsertTransparencyCheckpoint(_ context.Context, value verificationdomain.TransparencyCheckpoint) error {
	s.checkpoints[value.ID] = value
	return nil
}
func (s *verificationTestState) ReadObjectRetentionPolicy(_ context.Context, tenantID, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	value, ok := s.retentionPolicies[id]
	if !ok || value.TenantID != tenantID {
		return verificationdomain.ObjectRetentionPolicy{}, ErrNotFound
	}
	return cloneObjectRetentionPolicy(value), nil
}
func (s *verificationTestState) ReadSigningCustodySnapshot(_ context.Context, tenantID string) (SigningCustodySnapshot, error) {
	providers := make([]verificationdomain.SigningProvider, 0)
	for _, value := range s.providers {
		if value.TenantID == tenantID {
			providers = append(providers, value)
		}
	}
	policies := make([]verificationdomain.ObjectRetentionPolicy, 0)
	for _, value := range s.retentionPolicies {
		if value.TenantID == tenantID {
			policies = append(policies, cloneObjectRetentionPolicy(value))
		}
	}
	return SigningCustodySnapshot{TenantID: tenantID, SigningProviders: providers, ObjectRetentionPolicies: policies}, nil
}
func (s *verificationTestState) ReadCommittedBackupSnapshot(_ context.Context, _ string) (BackupSnapshot, error) {
	return cloneBackupSnapshot(s.backupSnapshot), nil
}
func (s *verificationTestState) VerifyRetention(_ context.Context, _ RetentionRequest) (RetentionObservation, bool, error) {
	return cloneRetentionObservation(s.retentionObservation), s.retentionConfigured, s.retentionErr
}
func (s *verificationTestState) GetObjectRetentionPolicyForUpdate(ctx context.Context, tenantID, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	return s.ReadObjectRetentionPolicy(ctx, tenantID, id)
}
func (s *verificationTestState) InsertObjectRetentionPolicy(_ context.Context, value verificationdomain.ObjectRetentionPolicy) error {
	s.retentionPolicies[value.ID] = cloneObjectRetentionPolicy(value)
	return nil
}
func (s *verificationTestState) UpdateObjectRetentionPolicy(_ context.Context, value verificationdomain.ObjectRetentionPolicy, expectedStatus string) error {
	current, ok := s.retentionPolicies[value.ID]
	if !ok || current.TenantID != value.TenantID {
		return ErrNotFound
	}
	if current.Status != expectedStatus {
		return ErrConflict
	}
	s.retentionPolicies[value.ID] = cloneObjectRetentionPolicy(value)
	return nil
}
func (s *verificationTestState) InsertBackupManifest(_ context.Context, value verificationdomain.BackupManifest) error {
	s.backupManifests[value.ID] = cloneBackupManifest(value)
	return nil
}
func (s *verificationTestState) AppendAudit(_ context.Context, value application.AuditEvent) (application.AuditReceipt, error) {
	if s.auditErr != nil {
		return application.AuditReceipt{}, s.auditErr
	}
	s.audit = append(s.audit, value)
	return application.AuditReceipt{ID: value.ID}, nil
}
func (s *verificationTestState) EnqueueOutbox(_ context.Context, value application.OutboxEvent) error {
	s.outbox = append(s.outbox, value)
	return nil
}

type verificationTestTransaction struct{ state *verificationTestState }

func (t verificationTestTransaction) Verification() Repository { return t.state }
func (t verificationTestTransaction) Authorization() application.Authorizer {
	return allowVerificationAuthorizer{}
}
func (t verificationTestTransaction) Audit() application.AuditAppender   { return t.state }
func (t verificationTestTransaction) Outbox() application.OutboxEnqueuer { return t.state }
