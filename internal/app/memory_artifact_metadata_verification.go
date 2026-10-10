package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

var _ verificationapp.ArtifactSignatureVerificationReader = memoryVerificationRepository{}

// Current artifact binding, digest labels and presence flags only. Raw
// signature/algorithm text, object references and trust roots are not selected.
func (r memoryVerificationRepository) ResolveArtifactSignatureVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	var out verificationapp.SubjectReference
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		sig, _, err := memoryCosignOwned(s, tenant, id)
		if err != nil {
			return err
		}
		if !memoryGovernanceText(sig.SubjectDigest, 1024) {
			return ErrConflict
		}
		out = verificationapp.SubjectReference{TenantID: tenant, Type: "artifact_signature", ID: id, Resources: application.ResourceReferences{ArtifactID: sig.ArtifactID}}
		return nil
	})
	if err != nil {
		return verificationapp.SubjectReference{}, err
	}
	return out, nil
}
func (r memoryVerificationRepository) ReadArtifactSignatureVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.ArtifactSignatureVerificationSnapshot, error) {
	var out verificationapp.ArtifactSignatureVerificationSnapshot
	if subject.Type != "artifact_signature" || subject.Resources.ArtifactID == "" || subject.Resources != (application.ResourceReferences{ArtifactID: subject.Resources.ArtifactID}) {
		return out, ErrValidation
	}
	err := memoryGovernanceRead(ctx, r.uow, subject.TenantID, subject.ID, func(s *MemoryUnitOfWorkSnapshot) error {
		sig, artifact, err := memoryCosignOwned(s, subject.TenantID, subject.ID)
		if err != nil {
			return err
		}
		if sig.ArtifactID != subject.Resources.ArtifactID || !memoryGovernanceText(sig.SubjectDigest, 1024) || !memoryGovernanceText(artifact.Digest, 1024) {
			return ErrConflict
		}
		out = verificationapp.ArtifactSignatureVerificationSnapshot{Subject: subject, SignatureDigest: sig.SubjectDigest, ArtifactDigest: artifact.Digest, AlgorithmPresent: sig.Algorithm != "", SignaturePresent: sig.Signature != ""}
		return nil
	})
	if err != nil {
		return verificationapp.ArtifactSignatureVerificationSnapshot{}, err
	}
	return out, nil
}
