package app

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Current typed fixture coordinates only. This models ownership, not the native
// common writer fence or PostgreSQL share locks, and never consults Ledger.
func (r memoryPackageRepository) LockCustomerPackageCreationScope(ctx context.Context, tenant, product, release string) error {
	if !memoryGovernanceText(release, packageapp.MaxCustomerPackageIDBytes) || strings.TrimSpace(release) != release {
		return ErrValidation
	}
	return memoryGovernanceRead(ctx, r.uow, tenant, product, func(s *MemoryUnitOfWorkSnapshot) error {
		_, err := memoryGovernanceProductRelease(s, tenant, product, release)
		return err
	})
}

// Historical policy reads preserve exact arrays rather than applying creation
// normalization. Only the selected owned policy is projected and detached.
func (r memoryPackageRepository) GetCustomerPackageRedactionProfile(ctx context.Context, tenant, id string) (packagedomain.RedactionProfile, error) {
	var out packagedomain.RedactionProfile
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		p, ok := s.RedactionProfiles[id]
		if !ok || p.ID != id || p.TenantID != tenant || p.Name == "" || p.SchemaVersion == "" || len(p.AllowedTypes) == 0 {
			return ErrNotFound
		}
		createdAt := p.CreatedAt.UTC()
		if !memoryGovernanceText(p.Name, packageapp.MaxRedactionProfileTextBytes) || !memoryGovernanceText(p.Description, packageapp.MaxRedactionProfileTextBytes) || !memoryGovernanceText(p.SchemaVersion, 1024) || createdAt.IsZero() || createdAt.Year() < 1 || createdAt.Year() > 9999 {
			return ErrConflict
		}
		for _, values := range [][]string{p.AllowedTypes, p.ExcludedFields} {
			if len(values) > packageapp.MaxRedactionProfileEntries {
				return ErrConflict
			}
			for _, v := range values {
				if !memoryGovernanceText(v, packageapp.MaxRedactionProfileEntryBytes) {
					return ErrConflict
				}
			}
		}
		raw, err := json.Marshal(p)
		if err != nil || len(raw) > packageapp.MaxCustomerPackageManifestBytes {
			return ErrConflict
		}
		out = packagedomain.RedactionProfile(p)
		out.AllowedTypes = slices.Clone(p.AllowedTypes)
		out.ExcludedFields = slices.Clone(p.ExcludedFields)
		out.CreatedAt = createdAt
		return ctx.Err()
	})
	if err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	return out, nil
}
