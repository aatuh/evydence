package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// Typed fixture snapshots hold one transaction view across scope, IDs, audit
// head and public retention facts. They neither inspect payloads nor establish
// native PostgreSQL repeatable-read, row-lock or pre-transfer guarantees.
var (
	_ packageapp.ReleaseBundleSnapshotReader  = memoryPackageRepository{}
	_ packageapp.EvidenceBundleSnapshotReader = memoryPackageRepository{}
)

func (r memoryPackageRepository) ReadReleaseBundleSnapshot(ctx context.Context, tenant, release string, at time.Time) (packageapp.ReleaseBundleSnapshot, error) {
	var out packageapp.ReleaseBundleSnapshot
	if !memoryCustomerSnapshotID(release, false) || at.IsZero() {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		product, err := memoryBundleReleaseParent(s, tenant, release)
		if err != nil {
			return err
		}
		v := s.Releases[release]
		if v.Version == "" || v.State == "" || !memoryGovernanceText(v.Version, 4096) || !memoryGovernanceText(v.State, 64) {
			return ErrConflict
		}
		ids, err := memoryBundleEvidenceIDs(ctx, s, tenant, release)
		if err != nil {
			return err
		}
		sequence, head, err := memoryBundleAuditHead(s, tenant)
		if err != nil {
			return err
		}
		budget := memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		proofs, err := readMemoryPublicRetention(ctx, s, tenant, at, &budget, packageapp.MaxBundleSnapshotRows-len(ids))
		if err != nil {
			return err
		}
		out = packageapp.ReleaseBundleSnapshot{SnapshotVersion: packageapp.ReleaseBundleSnapshotVersion, TenantID: tenant, ProductID: product, ReleaseID: release, ReleaseVersion: v.Version, ReleaseState: v.State, EvidenceIDs: ids, ChainSequence: sequence, ChainHeadHash: head, ObjectLockProofs: proofs}
		return ctx.Err()
	})
	if err != nil {
		return packageapp.ReleaseBundleSnapshot{}, err
	}
	return out, nil
}

func (r memoryPackageRepository) ReadEvidenceBundleSnapshot(ctx context.Context, tenant, release string, at time.Time) (packageapp.EvidenceBundleSnapshot, error) {
	var out packageapp.EvidenceBundleSnapshot
	if !memoryCustomerSnapshotID(release, true) || at.IsZero() {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		product := ""
		var err error
		if release != "" {
			product, err = memoryBundleReleaseParent(s, tenant, release)
			if err != nil {
				return err
			}
		}
		ids, err := memoryBundleEvidenceIDs(ctx, s, tenant, release)
		if err != nil {
			return err
		}
		budget := memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		proofs, err := readMemoryPublicRetention(ctx, s, tenant, at, &budget, packageapp.MaxBundleSnapshotRows-len(ids))
		if err != nil {
			return err
		}
		selected := make([]packageapp.EvidenceBundleEvidence, 0, len(ids))
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			refs, err := memoryBundleEvidenceCoordinates(s, tenant, id)
			if err != nil {
				return ErrConflict
			}
			selected = append(selected, packageapp.EvidenceBundleEvidence{ID: id, Resources: refs})
		}
		_, head, err := memoryBundleAuditHead(s, tenant)
		if err != nil {
			return err
		}
		out = packageapp.EvidenceBundleSnapshot{SnapshotVersion: packageapp.EvidenceBundleSnapshotVersion, TenantID: tenant, ProductID: product, ReleaseID: release, Evidence: selected, AuditChainHead: head, ObjectLockProofs: proofs}
		return ctx.Err()
	})
	if err != nil {
		return packageapp.EvidenceBundleSnapshot{}, err
	}
	return out, nil
}

func memoryBundleReleaseParent(s *MemoryUnitOfWorkSnapshot, tenant, release string) (string, error) {
	v, ok := s.Releases[release]
	if !ok || v.ID != release || v.TenantID != tenant {
		return "", ErrNotFound
	}
	if !memoryCustomerSnapshotID(v.ProductID, false) {
		return "", ErrConflict
	}
	p, ok := s.Products[v.ProductID]
	if !ok || p.ID != v.ProductID || p.TenantID != tenant {
		return "", ErrNotFound
	}
	return v.ProductID, nil
}

func memoryBundleEvidenceIDs(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, release string) ([]string, error) {
	ids := []string{}
	for key, v := range s.Evidence {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if v.TenantID != tenant || release != "" && v.ReleaseID != release {
			continue
		}
		if v.ID != key || !memoryCustomerSnapshotID(key, false) || len(ids) == packageapp.MaxBundleSnapshotRows {
			return nil, ErrConflict
		}
		ids = append(ids, key)
	}
	slices.Sort(ids)
	return ids, nil
}

func memoryBundleAuditHead(s *MemoryUnitOfWorkSnapshot, tenant string) (int, string, error) {
	var head domain.AuditChainEntry
	found := false
	for _, v := range s.AuditEntries[tenant] {
		if v.TenantID != tenant || found && v.Sequence <= head.Sequence {
			continue
		}
		head = v
		found = true
	}
	if !found {
		return 0, "", nil
	}
	if head.Sequence <= 0 || int64(int(head.Sequence)) != head.Sequence || head.EntryHash == "" || !memoryGovernanceText(head.EntryHash, 1024) {
		return 0, "", ErrConflict
	}
	return int(head.Sequence), head.EntryHash, nil
}

func memoryBundleEvidenceCoordinates(s *MemoryUnitOfWorkSnapshot, tenant, id string) (application.ResourceReferences, error) {
	v, ok := s.Evidence[id]
	if !ok || v.ID != id || v.TenantID != tenant {
		return application.ResourceReferences{}, ErrNotFound
	}
	refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: v.ProductID, ProjectID: v.ProjectID, ReleaseID: v.ReleaseID, BuildID: v.BuildID, DeploymentID: v.DeploymentID})
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrValidation) {
		return application.ResourceReferences{}, ErrConflict
	}
	return refs, err
}

func (r memoryPackageRepository) LockReleaseBundleParent(ctx context.Context, tenant, release string) (string, error) {
	if !memoryCustomerSnapshotID(release, false) {
		return "", ErrValidation
	}
	var product string
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		product, err = memoryBundleReleaseParent(s, tenant, release)
		return err
	})
	if err != nil {
		return "", err
	}
	return product, nil
}
func (r memoryPackageRepository) LockEvidenceBundleTenant(ctx context.Context, tenant string) error {
	return r.LockBundleImportTenant(ctx, tenant)
}
func (r memoryEvidenceRepository) LockEvidenceBundleEvidence(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	if !memoryCustomerSnapshotID(id, false) || strings.TrimSpace(id) != id {
		return application.ResourceReferences{}, ErrValidation
	}
	var out application.ResourceReferences
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryBundleEvidenceCoordinates(s, tenant, id)
		return err
	})
	if err != nil {
		return application.ResourceReferences{}, err
	}
	return out, nil
}
