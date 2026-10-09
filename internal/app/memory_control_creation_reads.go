package app

import (
	"context"

	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

var _ riskapp.ControlCreationReader = memoryControlRepository{}
var _ riskapp.ControlTemplateReader = memoryControlRepository{}

// Existence-only reads over the current typed snapshot. They do not transfer
// framework definitions or model native SQL fences/locks/durability.
func (r memoryControlRepository) LockControlCreationTenant(ctx context.Context, tenant string) error {
	return memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(*MemoryUnitOfWorkSnapshot) error { return nil })
}
func (r memoryControlRepository) LockControlTemplateTenant(ctx context.Context, tenant string) error {
	return r.LockControlCreationTenant(ctx, tenant)
}
func (r memoryControlRepository) FrameworkVersionExists(ctx context.Context, tenant, slug, version string) (bool, error) {
	var found bool
	err := memoryGovernanceRead(ctx, r.uow, tenant, slug, func(s *MemoryUnitOfWorkSnapshot) error {
		if version == "" || !memoryGovernanceText(version, 1024) || len(slug)+len(version) > 1024 {
			return ErrValidation
		}
		for id, v := range s.ControlFrameworks {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.ID == id && v.TenantID == tenant && v.Slug == slug && v.Version == version {
				found = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}
func (r memoryControlRepository) ControlFrameworkExists(ctx context.Context, tenant, id string) (bool, error) {
	var found bool
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.ControlFrameworks[id]
		found = ok && v.ID == id && v.TenantID == tenant
		return nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}
func (r memoryControlRepository) SecurityControlCodeExists(ctx context.Context, tenant, framework, code string) (bool, error) {
	var found bool
	err := memoryGovernanceRead(ctx, r.uow, tenant, framework, func(s *MemoryUnitOfWorkSnapshot) error {
		if code == "" || !memoryGovernanceText(code, 1024) || len(tenant)+len(framework)+len(code) > 2048 {
			return ErrValidation
		}
		f, ok := s.ControlFrameworks[framework]
		if !ok || f.ID != framework || f.TenantID != tenant {
			return nil
		}
		for id, v := range s.SecurityControls {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.ID == id && v.TenantID == tenant && v.FrameworkID == framework && v.Code == code {
				found = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}
