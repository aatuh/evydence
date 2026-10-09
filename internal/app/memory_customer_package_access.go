package app

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// Current typed package/product/release rows, never Ledger. This fixture model
// does not establish PostgreSQL mutation fences, row locks or transfer bounds.
func (r memoryPackageRepository) GetCustomerSecurityPackageForUpdate(ctx context.Context, tenant, id string) (domain.CustomerSecurityPackage, error) {
	var out domain.CustomerSecurityPackage
	if ctx == nil || r.uow == nil || strings.TrimSpace(tenant) == "" || strings.TrimSpace(id) == "" || !memoryGovernanceText(tenant, 1024) || !memoryGovernanceText(id, 1024) {
		return out, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		p, ok := s.CustomerPackages[id]
		if !ok || p.ID != id || p.TenantID != tenant || p.ProductID == "" {
			return ErrNotFound
		}
		product, ok := s.Products[p.ProductID]
		if !ok || product.ID != p.ProductID || product.TenantID != tenant {
			return ErrNotFound
		}
		if p.ReleaseID != "" {
			release, ok := s.Releases[p.ReleaseID]
			if !ok || release.ID != p.ReleaseID || release.TenantID != tenant || release.ProductID != p.ProductID {
				return ErrNotFound
			}
		}
		for _, field := range []struct {
			value string
			limit int
		}{{p.ID, 1024}, {p.ProductID, 1024}, {p.ReleaseID, 1024}, {p.RedactionProfileID, 1024}, {p.Title, 4096}, {p.State, 64}, {p.ManifestHash, 1024}, {p.SchemaVersion, 1024}} {
			if !memoryGovernanceText(field.value, field.limit) {
				return ErrConflict
			}
		}
		if p.Manifest == nil {
			return ErrConflict
		}
		remaining := packageapp.MaxCustomerPackageManifestBytes
		if !memoryCustomerMetadataFits(p.Manifest, &remaining, 0) {
			return ErrConflict
		}
		raw, err := json.Marshal(p.Manifest)
		if err != nil {
			return ErrConflict
		}
		bounds := memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		if err := bounds.chargeJSON(raw); err != nil {
			return err
		}
		out, err = cloneMemoryCustomerPackage(p)
		if err != nil {
			return ErrConflict
		}
		return ctx.Err()
	})
	if err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	return out, nil
}

// Match SQL's counter-only update. A redacted caller view, title or other DTO
// field cannot replace any immutable package field in the stored record.
func (r memoryPackageRepository) UpdateCustomerSecurityPackageAccess(ctx context.Context, previous, current domain.CustomerSecurityPackage) error {
	if ctx == nil || r.uow == nil || current.ID == "" || current.TenantID == "" || previous.ID != current.ID || previous.TenantID != current.TenantID || previous.AccessCount < 0 || previous.AccessCount >= math.MaxInt32 || current.AccessCount != previous.AccessCount+1 {
		return ErrValidation
	}
	return r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		stored, ok := s.CustomerPackages[current.ID]
		if !ok || stored.ID != current.ID || stored.TenantID != current.TenantID {
			return ErrNotFound
		}
		if stored.AccessCount != previous.AccessCount || stored.ManifestHash != current.ManifestHash || stored.State != current.State || !stored.ExpiresAt.Equal(current.ExpiresAt) {
			return ErrConflict
		}
		stored.AccessCount = current.AccessCount
		s.CustomerPackages[stored.ID] = stored
		return ctx.Err()
	})
}

// Frozen manifest JSON must not round through float64 on insertion, commit,
// snapshot or access. Full snapshots may include incomplete test seed rows;
// selected point readers apply their projection bounds separately.
func cloneMemoryCustomerPackage(p domain.CustomerSecurityPackage) (domain.CustomerSecurityPackage, error) {
	raw, err := json.Marshal(p.Manifest)
	if err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	var manifest map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&manifest); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	p.Manifest = manifest
	return p, nil
}
