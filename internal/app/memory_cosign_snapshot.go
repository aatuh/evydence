package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

var _ verificationapp.CosignSnapshotReader = memoryVerificationRepository{}
var _ verificationapp.CosignVerificationScopeLocker = memoryVerificationRepository{}

// Typed transaction facts mirror selected native coordinates and lifecycle
// metadata, not PostgreSQL fences, JSON shapes, row locks or durability.
func memoryCosignOwned(s *MemoryUnitOfWorkSnapshot, tenant, id string) (domain.ArtifactSignature, domain.Artifact, error) {
	sig, ok := s.ArtifactSignatures[id]
	if !ok || sig.ID != id || sig.TenantID != tenant {
		return domain.ArtifactSignature{}, domain.Artifact{}, ErrNotFound
	}
	if sig.ArtifactID == "" || strings.TrimSpace(sig.ArtifactID) != sig.ArtifactID || !memoryGovernanceText(sig.ArtifactID, 1024) {
		return domain.ArtifactSignature{}, domain.Artifact{}, ErrConflict
	}
	a, ok := s.Artifacts[sig.ArtifactID]
	if !ok || a.ID != sig.ArtifactID || a.TenantID != tenant {
		return domain.ArtifactSignature{}, domain.Artifact{}, ErrNotFound
	}
	return sig, a, nil
}
func (r memoryVerificationRepository) LockCosignVerificationScope(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	var out application.ResourceReferences
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		sig, _, err := memoryCosignOwned(s, tenant, id)
		if err != nil {
			return err
		}
		out = application.ResourceReferences{ArtifactID: sig.ArtifactID}
		return nil
	})
	if err != nil {
		return application.ResourceReferences{}, err
	}
	return out, nil
}
func (r memoryVerificationRepository) ResolveCosignSubject(ctx context.Context, tenant, id string) (verificationapp.CosignSubject, error) {
	var out verificationapp.CosignSubject
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		sig, _, err := memoryCosignOwned(s, tenant, id)
		if err != nil {
			return err
		}
		if sig.SubjectDigest == "" || !memoryGovernanceText(sig.SubjectDigest, 1024) {
			return ErrConflict
		}
		out = verificationapp.CosignSubject{TenantID: tenant, ArtifactSignatureID: id, ArtifactID: sig.ArtifactID, SubjectDigest: sig.SubjectDigest, Resources: application.ResourceReferences{ArtifactID: sig.ArtifactID}}
		for key, image := range s.ContainerImages {
			if err := ctx.Err(); err != nil {
				return err
			}
			if image.TenantID == tenant && image.ArtifactID == sig.ArtifactID && image.Digest == sig.SubjectDigest && (out.ContainerImageID == "" || key < out.ContainerImageID) {
				out.ContainerImageID = key
			}
		}
		if out.ContainerImageID != "" && (s.ContainerImages[out.ContainerImageID].ID != out.ContainerImageID || !memoryGovernanceText(out.ContainerImageID, 1024)) {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return verificationapp.CosignSubject{}, err
	}
	return out, nil
}
func (r memoryVerificationRepository) ReadCosignSnapshot(ctx context.Context, subject verificationapp.CosignSubject) (verificationapp.CosignSnapshot, error) {
	var out verificationapp.CosignSnapshot
	err := memoryGovernanceRead(ctx, r.uow, subject.TenantID, subject.ArtifactSignatureID, func(s *MemoryUnitOfWorkSnapshot) error {
		sig, a, err := memoryCosignOwned(s, subject.TenantID, subject.ArtifactSignatureID)
		if err != nil {
			return err
		}
		if sig.ArtifactID != subject.ArtifactID || sig.SubjectDigest != subject.SubjectDigest {
			return ErrConflict
		}
		for _, text := range []struct {
			v string
			n int
		}{{sig.SubjectDigest, 1024}, {sig.Algorithm, 64}, {sig.PayloadRef, 4096}, {sig.PayloadHash, 1024}, {a.Digest, 1024}} {
			if !memoryGovernanceText(text.v, text.n) {
				return ErrConflict
			}
		}
		out = verificationapp.CosignSnapshot{Subject: subject, ArtifactDigest: a.Digest, Algorithm: sig.Algorithm, PayloadRef: sig.PayloadRef, PayloadHash: sig.PayloadHash}
		if sig.PayloadHash == "" {
			return nil
		}
		p, ok := s.ObjectPayloads[memoryObjectPayloadKey(subject.TenantID, sig.PayloadHash)]
		if !ok {
			return nil
		}
		if p.TenantID != subject.TenantID || p.Digest != sig.PayloadHash {
			return ErrConflict
		}
		if !memoryGovernanceText(p.FinalKey, 4096) || !memoryGovernanceText(p.MediaType, 4096) || !memoryGovernanceText(string(p.Status), 64) || p.Size < 0 || p.Size > verificationapp.MaxCosignPayloadBytes {
			return ErrConflict
		}
		out.PayloadMediaType, out.PayloadSize = p.MediaType, p.Size
		_, canonical, err := CanonicalObjectPayloadKeys(subject.TenantID, sig.PayloadHash)
		out.PayloadFinalized = err == nil && p.Status == ObjectPayloadFinalized && p.FinalKey == canonical && sig.PayloadRef == "object://"+canonical
		return nil
	})
	if err != nil {
		return verificationapp.CosignSnapshot{}, err
	}
	return out, nil
}
