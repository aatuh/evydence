package app

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const MaxCosignPayloadBytes = 4 << 20

// CosignSnapshot excludes detached signature text and unrelated tenant state.
// The reader holds the selected signature/artifact/payload locks until receipts
// and the audit entry commit. Missing/unfinalized payloads are failed facts,
// never an invitation to trust caller-supplied metadata or use online fallback.
type CosignSnapshot struct {
	Subject          CosignSubject
	ArtifactDigest   string
	Algorithm        string
	PayloadRef       string
	PayloadHash      string
	PayloadSize      int64
	PayloadMediaType string
	PayloadFinalized bool
}
type CosignSnapshotReader interface {
	CosignSubjectResolver
	ReadCosignSnapshot(context.Context, CosignSubject) (CosignSnapshot, error)
}
type cosignReceiptTransaction interface {
	application.AuditAppender
	InsertVerificationResult(context.Context, verificationdomain.VerificationResult) error
	InsertCosignVerification(context.Context, verificationdomain.CosignVerification) error
}
type CosignVerificationTransaction interface {
	CosignSnapshotReader
	application.Authorizer
	cosignReceiptTransaction
}
type CosignVerificationTransactions interface {
	ExecuteCosignVerification(context.Context, func(context.Context, CosignVerificationTransaction) error) error
}
type CosignSnapshotInspector interface {
	InspectCosignSnapshot(context.Context, CosignSnapshot, VerifyCosignInput) (CosignInspection, error)
}
type CosignVerificationConfig struct {
	Transactions CosignVerificationTransactions
	Authorizer   application.Authorizer
	Inspector    CosignSnapshotInspector
	Clock        application.Clock
	IDs          application.IDGenerator
}
type CosignVerificationCommands struct{ config CosignVerificationConfig }

func NewCosignVerificationCommands(c CosignVerificationConfig) (*CosignVerificationCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Inspector == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &CosignVerificationCommands{c}, nil
}
func (c *CosignVerificationCommands) VerifyCosign(ctx context.Context, actor identitydomain.Actor, input VerifyCosignInput) (verificationdomain.CosignVerification, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	if err := c.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	input.ArtifactSignatureID = strings.TrimSpace(input.ArtifactSignatureID)
	input.ExpectedIdentity = strings.TrimSpace(input.ExpectedIdentity)
	input.ExpectedIssuer = strings.TrimSpace(input.ExpectedIssuer)
	if !validCosignInput(input) || !validRetentionText(input.ArtifactSignatureID, 1024) || len(input.ExpectedIdentity) > 4096 || len(input.ExpectedIssuer) > 4096 || !validOptionalCosignText(input.ExpectedIdentity) || !validOptionalCosignText(input.ExpectedIssuer) {
		return verificationdomain.CosignVerification{}, ErrValidation
	}
	var record verificationdomain.CosignVerification
	var outcome string
	err := c.config.Transactions.ExecuteCosignVerification(ctx, func(ctx context.Context, tx CosignVerificationTransaction) error {
		subject, err := tx.ResolveCosignSubject(ctx, actor.TenantID, input.ArtifactSignatureID)
		if err != nil {
			return err
		}
		if !validCosignSubject(subject, actor.TenantID, input.ArtifactSignatureID) || subject.Resources != (application.ResourceReferences{ArtifactID: subject.ArtifactID}) {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, Resources: subject.Resources}); err != nil {
			return err
		}
		snapshot, err := tx.ReadCosignSnapshot(ctx, subject)
		if err != nil {
			return err
		}
		if snapshot.Subject != subject || !boundedCosignSnapshot(snapshot) {
			return ErrConflict
		}
		inspection, err := c.config.Inspector.InspectCosignSnapshot(ctx, snapshot, input)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		outcome = inspection.Outcome
		record, err = persistCosignReceipt(ctx, tx, actor, subject, inspection, input.Mode, c.config.Clock.Now().UTC(), c.config.IDs)
		return err
	})
	if err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	return cloneCosignVerification(record), cosignOutcomeError(outcome, record.Result)
}
func validOptionalCosignText(s string) bool { return s == "" || validSigningKeyText(s) }
func boundedCosignSnapshot(s CosignSnapshot) bool {
	for _, v := range []string{s.Subject.TenantID, s.Subject.ArtifactID, s.Subject.ArtifactSignatureID, s.Subject.ContainerImageID, s.Subject.SubjectDigest, s.ArtifactDigest, s.Algorithm, s.PayloadRef, s.PayloadHash, s.PayloadMediaType} {
		if len(v) > 4096 || !validOptionalCosignText(v) {
			return false
		}
	}
	return s.PayloadSize >= 0 && s.PayloadSize <= MaxCosignPayloadBytes
}

// CosignFullProfile is shared by durable and explicit local-memory inspection.
func CosignFullProfile(mode CosignVerificationMode, digest string) verificationdomain.VerificationProfile {
	required := []string{"sigstore_bundle", "subject_digest", "cryptographic_signature", "rekor_inclusion_proof"}
	identity := "configured key-based signing trust material"
	if mode == CosignVerificationModeKeyless {
		required = append(required, "fulcio_trust_root", "certificate_validity", "certificate_identity_policy")
		identity = "caller-supplied expected certificate identity and issuer"
	} else {
		required = append(required, "trusted_public_key")
	}
	return verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{ID: verificationdomain.VerificationProfileCosignFull, Version: verificationdomain.VerificationProfileSchemaVersion, RequiredChecks: required, TrustMaterial: []string{"configured Sigstore trust root or public key"}, IdentityPolicy: identity, TransparencyProof: "embedded Rekor inclusion proof verified offline", PayloadScope: "artifact digest and signed Sigstore bundle", PayloadDigest: digest, Limitations: []string{"This profile verifies an explicit offline bundle only. Online-required verification is rejected instead of downgraded."}})
}

// Artifact digest labels historically accept either hexadecimal case. Object
// payload identity separately requires canonical lowercase SHA-256 keys.
func ValidCosignSubjectDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func persistCosignReceipt(ctx context.Context, tx cosignReceiptTransaction, actor identitydomain.Actor, subject CosignSubject, inspection CosignInspection, mode CosignVerificationMode, now time.Time, ids application.IDGenerator) (verificationdomain.CosignVerification, error) {
	inspection = cloneCosignInspection(inspection)
	// Required assurance belongs to core policy, never an adapter-supplied
	// subset of checks that could silently downgrade full verification.
	inspection.Profile = CosignFullProfile(mode, subject.SubjectDigest)
	if !validCosignInspection(inspection) {
		return verificationdomain.CosignVerification{}, ErrValidation
	}
	state := verificationdomain.AggregateVerificationState(inspection.Profile, inspection.Checks)
	if inspection.Outcome != "" && state.String() == "passed" {
		return verificationdomain.CosignVerification{}, ErrValidation
	}
	record := verificationdomain.CosignVerification{ID: ids.NewID("cosv"), TenantID: actor.TenantID, ArtifactID: subject.ArtifactID, ContainerImageID: subject.ContainerImageID, ArtifactSignatureID: subject.ArtifactSignatureID, SubjectDigest: subject.SubjectDigest, CertificateIdentity: inspection.CertificateIdentity, CertificateIssuer: inspection.CertificateIssuer, VerifierLibraryVersion: inspection.LibraryVersion, TrustRootVersion: inspection.TrustRootVersion, VerificationMode: string(mode), Result: state.String(), Checks: inspection.Checks, Profile: inspection.Profile, Limitations: inspection.Limitations, SchemaVersion: verificationdomain.CosignVerificationSchemaVersion, CreatedAt: now}
	verification := verificationdomain.VerificationResult{ID: record.ID, TenantID: actor.TenantID, SubjectType: "artifact_signature", SubjectID: subject.ArtifactSignatureID, Result: state, Checks: append([]verificationdomain.VerifyCheck(nil), inspection.Checks...), Profile: cloneVerificationProfile(inspection.Profile), Limitations: append([]string(nil), inspection.Profile.Limitations...), SchemaVersion: verificationdomain.VerificationResultSchemaVersion, VerifiedAt: now}
	if err := tx.InsertCosignVerification(ctx, record); err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	if err := tx.InsertVerificationResult(ctx, verification); err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	_, err := tx.AppendAudit(ctx, application.AuditEvent{ID: ids.NewID("ace"), TenantID: actor.TenantID, EntryType: "cosign_signature.verified", SubjectType: "artifact_signature", SubjectID: subject.ArtifactSignatureID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), PayloadHash: subject.SubjectDigest, OccurredAt: now})
	if err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	return record, nil
}
func cosignOutcomeError(outcome, result string) error {
	switch outcome {
	case CosignOutcomeUnavailable:
		return ErrFullVerificationUnavailable
	case CosignOutcomeVerificationFailed:
		return ErrVerificationFailed
	}
	// This command explicitly requires the full profile. A limited or missing
	// receipt cannot turn into HTTP success merely because no required check
	// was evaluated; it is not a metadata-assessment endpoint.
	if result != "passed" {
		return ErrVerificationFailed
	}
	return nil
}
