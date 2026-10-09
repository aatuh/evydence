package app

import "context"

func (r memoryPackageRepository) LockReportTemplateTenant(ctx context.Context, tenant string) error {
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error { return requireMemoryTenant(*state, tenant) })
}
func (r memoryPackageRepository) LockReportTemplateIdentity(ctx context.Context, tenant, id string) error {
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, tenant); err != nil {
			return err
		}
		v, ok := state.ReportTemplates[id]
		if !ok || v.TenantID != tenant {
			return ErrNotFound
		}
		return nil
	})
}
