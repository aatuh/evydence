package app

import "context"

func (r memoryPackageRepository) LockBundleImportTenant(ctx context.Context, tenant string) error {
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error { return requireMemoryTenant(*state, tenant) })
}
