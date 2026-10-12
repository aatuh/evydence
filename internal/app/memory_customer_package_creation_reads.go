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
		var err error
		out, err = readMemoryCustomerRedactionProfile(s, tenant, id)
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	return out, nil
}

func readMemoryCustomerRedactionProfile(s *MemoryUnitOfWorkSnapshot, tenant, id string) (packagedomain.RedactionProfile, error) {
	p, ok := s.RedactionProfiles[id]
	if !ok || p.ID != id || p.TenantID != tenant || p.Name == "" || p.SchemaVersion == "" || len(p.AllowedTypes) == 0 {
		return packagedomain.RedactionProfile{}, ErrNotFound
	}
	p.CreatedAt = p.CreatedAt.UTC()
	if !memoryGovernanceText(p.Name, packageapp.MaxRedactionProfileTextBytes) || !memoryGovernanceText(p.Description, packageapp.MaxRedactionProfileTextBytes) || !memoryGovernanceText(p.SchemaVersion, 1024) || p.CreatedAt.IsZero() || p.CreatedAt.Year() < 1 || p.CreatedAt.Year() > 9999 {
		return packagedomain.RedactionProfile{}, ErrConflict
	}
	for _, values := range [][]string{p.AllowedTypes, p.ExcludedFields} {
		if len(values) > packageapp.MaxRedactionProfileEntries {
			return packagedomain.RedactionProfile{}, ErrConflict
		}
		for _, v := range values {
			if !memoryGovernanceText(v, packageapp.MaxRedactionProfileEntryBytes) {
				return packagedomain.RedactionProfile{}, ErrConflict
			}
		}
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > packageapp.MaxCustomerPackageManifestBytes {
		return packagedomain.RedactionProfile{}, ErrConflict
	}
	out := packagedomain.RedactionProfile(p)
	out.AllowedTypes, out.ExcludedFields = slices.Clone(p.AllowedTypes), slices.Clone(p.ExcludedFields)
	return out, nil
}
