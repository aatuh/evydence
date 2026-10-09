package app

import (
	"context"
	"strings"

	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

var _ integrationapp.CollectorWriteReader = memoryBuildRepository{}

// Boolean identity reads inspect current typed coordinates, not credential,
// scope or descriptive metadata. Snapshot protection is not a native SQL fence.
func (r memoryBuildRepository) collectorKeyExists(ctx context.Context, tenant string, parts []string, read func(*MemoryUnitOfWorkSnapshot) (bool, error)) (bool, error) {
	var out bool
	err := memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		size := len(tenant)
		for _, value := range parts {
			if value == "" || strings.TrimSpace(value) != value || !memoryGovernanceText(value, integrationapp.MaxCollectorKeyBytes) {
				return ErrValidation
			}
			size += len(value)
		}
		if size > integrationapp.MaxCollectorKeyBytes {
			return ErrValidation
		}
		var err error
		out, err = read(s)
		return err
	})
	if err != nil {
		return false, err
	}
	return out, nil
}

func (r memoryBuildRepository) CollectorNameExists(ctx context.Context, tenant, name string) (bool, error) {
	return r.collectorKeyExists(ctx, tenant, []string{name}, func(s *MemoryUnitOfWorkSnapshot) (bool, error) {
		for _, v := range s.Collectors {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if v.TenantID == tenant && v.Name == name {
				return true, nil
			}
		}
		return false, nil
	})
}

func (r memoryBuildRepository) CommercialCollectorIdentityExists(ctx context.Context, tenant, provider, name, version string) (bool, error) {
	return r.collectorKeyExists(ctx, tenant, []string{provider, name, version}, func(s *MemoryUnitOfWorkSnapshot) (bool, error) {
		for _, v := range s.CommercialCollectors {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if v.TenantID == tenant && v.Provider == provider && v.Name == name && v.Version == version {
				return true, nil
			}
		}
		return false, nil
	})
}
