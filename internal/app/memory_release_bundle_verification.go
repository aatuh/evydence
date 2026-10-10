package app

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
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
		seen := map[string]bool{}
		keys := map[string]bool{}
		ids := slices.Clone(b.SignatureRefs)
		slices.Sort(ids)
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !memoryCustomerSnapshotID(id, false) || seen[id] {
				return ErrConflict
			}
			seen[id] = true
			v, ok := s.Signatures[id]
			if !ok || v.TenantID != subject.TenantID {
				continue
			}
			if v.ID != id {
				return ErrConflict
			}
			for _, field := range []struct {
				v string
				n int
			}{{v.ID, 1024}, {v.TenantID, 1024}, {v.SubjectType, 64}, {v.SubjectID, 1024}, {v.KeyID, 1024}, {v.Algorithm, 64}, {v.Value, 16384}} {
				if !memoryGovernanceText(field.v, field.n) {
					return ErrConflict
				}
			}
			public := verificationdomain.Signature(v)
			raw, err := json.Marshal(public)
			if err != nil {
				return ErrConflict
			}
			if err := budget.chargeJSON(raw); err != nil {
				return err
			}
			out.Signatures = append(out.Signatures, public)
			keys[v.KeyID] = true
		}
		keyIDs := make([]string, 0, len(keys))
		for id := range keys {
			keyIDs = append(keyIDs, id)
		}
		slices.Sort(keyIDs)
		for _, id := range keyIDs {
			if err := ctx.Err(); err != nil {
				return err
			}
			v, ok := s.SigningKeys[id]
			if !ok || v.TenantID != subject.TenantID {
				continue
			}
			if v.ID != id {
				return ErrConflict
			}
			for _, field := range []struct {
				v string
				n int
			}{{v.ID, 1024}, {v.TenantID, 1024}, {v.Algorithm, 64}, {v.PublicKey, 16384}, {v.Status, 64}, {v.RevocationSemantics, 64}, {v.HistoricalValidityPolicy, 64}} {
				if !memoryGovernanceText(field.v, field.n) {
					return ErrConflict
				}
			}
			status := v.Status
			if status == "" {
				status = verificationdomain.SigningKeyStatusLegacyUnspecifiedValue
			}
			parsed, err := verificationdomain.ParseSigningKeyStatus(status)
			if err != nil {
				return ErrConflict
			}
			public := verificationdomain.SigningKey{ID: v.ID, TenantID: v.TenantID, Algorithm: v.Algorithm, Status: parsed, PublicKey: v.PublicKey, CreatedAt: v.CreatedAt, ValidFrom: v.ValidFrom, ValidUntil: cloneTimePtr(v.ValidUntil), RevokedAt: cloneTimePtr(v.RevokedAt), CompromisedAt: cloneTimePtr(v.CompromisedAt), RevocationSemantics: v.RevocationSemantics, HistoricalValidityPolicy: v.HistoricalValidityPolicy}
			raw, err := json.Marshal(public)
			if err != nil {
				return ErrConflict
			}
			if err := budget.chargeJSON(raw); err != nil {
				return err
			}
			out.Keys = append(out.Keys, public)
		}
		return ctx.Err()
	})
	if err != nil {
		return verificationapp.ReleaseBundleVerificationSnapshot{}, err
	}
	return out, nil
}
