package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// This projection intentionally excludes algorithm text, signature bytes,
// payload references and configured trust: it can assess metadata, not trust.
type ArtifactSignatureVerificationSnapshot struct {
	Subject          SubjectReference
	SignatureDigest  string
	ArtifactDigest   string
	AlgorithmPresent bool
	SignaturePresent bool
}
type ArtifactSignatureVerificationReader interface {
	ResolveArtifactSignatureVerificationSubject(context.Context, string, string) (SubjectReference, error)
	ReadArtifactSignatureVerification(context.Context, SubjectReference) (ArtifactSignatureVerificationSnapshot, error)
}
type ArtifactSignatureVerificationTransaction interface {
	ArtifactSignatureVerificationReader
	application.Authorizer
	verificationReceiptTransaction
}
type ArtifactSignatureVerificationTransactions interface {
	ExecuteArtifactSignatureVerification(context.Context, func(context.Context, ArtifactSignatureVerificationTransaction) error) error
}
type ArtifactSignatureVerificationConfig struct {
	Transactions ArtifactSignatureVerificationTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ArtifactSignatureVerificationCommands struct {
	config ArtifactSignatureVerificationConfig
}

func NewArtifactSignatureVerificationCommands(c ArtifactSignatureVerificationConfig) (*ArtifactSignatureVerificationCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &ArtifactSignatureVerificationCommands{c}, nil
}
func (c *ArtifactSignatureVerificationCommands) VerifyArtifactSignature(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := c.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	id = strings.TrimSpace(id)
	if !validRetentionText(id, 1024) {
		return verificationdomain.VerificationResult{}, ErrValidation
	}
	var result verificationdomain.VerificationResult
	err := c.config.Transactions.ExecuteArtifactSignatureVerification(ctx, func(ctx context.Context, tx ArtifactSignatureVerificationTransaction) error {
		subject, err := tx.ResolveArtifactSignatureVerificationSubject(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if !validSubjectReference(subject, actor.TenantID, "artifact_signature", id) || subject.Resources.ArtifactID == "" || subject.Resources != (application.ResourceReferences{ArtifactID: subject.Resources.ArtifactID}) {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, Resources: subject.Resources}); err != nil {
			return err
		}
		snapshot, err := tx.ReadArtifactSignatureVerification(ctx, subject)
		if err != nil {
			return err
		}
		if snapshot.Subject != subject || !validRetentionText(snapshot.ArtifactDigest, 1024) || !validRetentionText(snapshot.SignatureDigest, 1024) {
			return ErrConflict
		}
		result, err = persistVerificationReceipt(ctx, tx, actor, subject, InspectArtifactSignatureMetadata(snapshot), c.config.Clock.Now().UTC(), c.config.IDs)
		return err
	})
	if err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if verificationReturnsFailure(result.Result) {
		return cloneVerificationResult(result), ErrVerificationFailed
	}
	return cloneVerificationResult(result), nil
}

// InspectArtifactSignatureMetadata preserves the metadata-only profile for
// both durable commands and the explicit local-memory compatibility path.
func InspectArtifactSignatureMetadata(s ArtifactSignatureVerificationSnapshot) SubjectInspection {
	binding, material := "passed", "passed"
	if s.ArtifactDigest != s.SignatureDigest {
		binding = "failed"
	}
	if !s.AlgorithmPresent || !s.SignaturePresent {
		material = "failed"
	}
	checks := []verificationdomain.VerifyCheck{{Name: "digest_binding_assessed", Result: binding}, {Name: "signature_material_present", Result: material}}
	if material == "passed" {
		checks[1].Detail = "signature recorded; cryptographic trust-root verification is deferred"
	}
	p := verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{ID: verificationdomain.VerificationProfileArtifactSignatureMetadata, Version: verificationdomain.VerificationProfileSchemaVersion, RequiredChecks: []string{"digest_binding_assessed", "signature_material_present", "cryptographic_signature_verified", "certificate_identity_policy", "transparency_inclusion_proof"}, TrustMaterial: []string{"recorded artifact signature metadata"}, IdentityPolicy: "no certificate identity policy evaluated", TransparencyProof: "not_evaluated", PayloadScope: "artifact digest and detached signature metadata", PayloadDigest: s.SignatureDigest, Limitations: []string{"This profile is metadata-only and cannot verify cryptographic signature validity, certificate identity, trust roots, or transparency inclusion."}})
	return SubjectInspection{Profile: p, Checks: checks}
}
