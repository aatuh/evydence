package app

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

var _ verificationapp.ReleaseBundleVerificationReader = memoryVerificationRepository{}

// Current typed fixture rows and public material only; not a model of SQL
// ownership/key locking, transport bounds or durability.
func memoryReleaseBundleSubject(s *MemoryUnitOfWorkSnapshot, tenant, id string) (verificationapp.SubjectReference, error) {
	b, ok := s.ReleaseBundles[id]
	if !ok || b.ID != id || b.TenantID != tenant {
		return verificationapp.SubjectReference{}, ErrNotFound
	}
	product, err := memoryBundleReleaseParent(s, tenant, b.ReleaseID)
	if err != nil {
		return verificationapp.SubjectReference{}, err
	}
	return verificationapp.SubjectReference{TenantID: tenant, Type: "release_bundle", ID: id, Resources: application.ResourceReferences{ProductID: product, ReleaseID: b.ReleaseID}}, nil
}
func (r memoryVerificationRepository) ResolveReleaseBundleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	if !memoryCustomerSnapshotID(id, false) {
		return verificationapp.SubjectReference{}, ErrValidation
	}
	var out verificationapp.SubjectReference
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryReleaseBundleSubject(s, tenant, id)
		return err
	})
	if err != nil {
		return verificationapp.SubjectReference{}, err
	}
	return out, nil
}
func (r memoryVerificationRepository) ReadReleaseBundleVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.ReleaseBundleVerificationSnapshot, error) {
	var out verificationapp.ReleaseBundleVerificationSnapshot
	if subject.Type != "release_bundle" || !memoryCustomerSnapshotID(subject.ID, false) {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, subject.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		current, err := memoryReleaseBundleSubject(s, subject.TenantID, subject.ID)
		if err != nil {
			return err
		}
		if current != subject {
			return ErrConflict
		}
		b := s.ReleaseBundles[subject.ID]
		if b.Manifest == nil || b.SignatureRefs == nil || len(b.SignatureRefs) > verificationapp.MaxBundleVerificationSignatures || !memoryGovernanceText(b.ManifestHash, 1024) {
			return ErrConflict
		}
		budget := memoryCustomerSnapshotBudget{remainingBytes: verificationapp.MaxBundleVerificationBytes}
		if err := budget.charge(map[string]any{"manifest": b.Manifest, "manifest_hash": b.ManifestHash, "signature_refs": b.SignatureRefs}); err != nil {
			return err
		}
		b, err = cloneMemoryReleaseBundle(b)
		if err != nil {
			return ErrConflict
		}
		out = verificationapp.ReleaseBundleVerificationSnapshot{Subject: subject, Manifest: b.Manifest, ManifestHash: b.ManifestHash, SignatureRefs: slices.Clone(b.SignatureRefs)}
		var material memoryVerificationPublicMaterial
		if err := readMemoryVerificationPublicMaterial(ctx, s, subject.TenantID, b.SignatureRefs, &budget, &material); err != nil {
			return err
		}
		out.Signatures, out.Keys = material.Signatures, material.Keys
		return ctx.Err()
	})
	if err != nil {
		return verificationapp.ReleaseBundleVerificationSnapshot{}, err
	}
	return out, nil
}
