package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

var _ verificationapp.SubjectVerificationScopeReader = memoryVerificationRepository{}

// Identity-only current facts for replay. No digest, payload, signing policy,
// receipt or audit-chain inspection is part of this test-backend read.
func (r memoryVerificationRepository) ResolveSubjectVerificationScope(ctx context.Context, tenant, kind, id string) (verificationapp.SubjectReference, error) {
	var out verificationapp.SubjectReference
	k, normalized, err := verificationapp.NormalizeSubjectVerificationInput(kind, id)
	if err != nil || k != kind || normalized != id {
		return out, ErrValidation
	}
	err = memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		var refs application.ResourceReferences
		var err error
		switch kind {
		case "audit_chain":
		case "evidence_item":
			refs, err = memoryBundleEvidenceCoordinates(s, tenant, id)
		case "build_attestation":
			refs, err = memoryDSSECoordinates(s, tenant, id)
		case "release_bundle", "audit_chain_release_manifest":
			b, ok := s.ReleaseBundles[id]
			if !ok || b.ID != id || b.TenantID != tenant {
				return ErrNotFound
			}
			var product string
			product, err = memoryBundleReleaseParent(s, tenant, b.ReleaseID)
			if kind == "release_bundle" {
				refs = application.ResourceReferences{ProductID: product, ReleaseID: b.ReleaseID}
			}
		case "artifact_signature":
			sig, _, readErr := memoryCosignOwned(s, tenant, id)
			err = readErr
			refs.ArtifactID = sig.ArtifactID
		case "merkle_batch", "audit_chain_checkpoint":
			b, ok := s.MerkleBatches[id]
			if !ok || b.ID != id || b.TenantID != tenant {
				return ErrNotFound
			}
		case "backup_manifest":
			b, ok := s.BackupManifests[id]
			if !ok || b.ID != id || b.TenantID != tenant {
				return ErrNotFound
			}
		default:
			return ErrValidation
		}
		if err != nil {
			return err
		}
		out = verificationapp.SubjectReference{TenantID: tenant, Type: kind, ID: id, Resources: refs}
		return nil
	})
	if err != nil {
		return verificationapp.SubjectReference{}, err
	}
	return out, nil
}
