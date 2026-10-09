package app

import (
	"context"
	"strings"
	"unicode/utf8"

	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

var _ releaseapp.CatalogCreationGuardReader = memoryReleaseCatalogRepository{}

// The memory transaction already serializes its pending snapshot. These are
// read-only test/local adapter equivalents, not PostgreSQL lock guarantees.
func (r memoryReleaseCatalogRepository) LockCatalogCreationTenant(ctx context.Context, tenant string) error {
	if tenant == "" || len(tenant) > 1024 || !utf8.ValidString(tenant) || strings.ContainsRune(tenant, 0) || strings.TrimSpace(tenant) != tenant {
		return ErrValidation
	}
	return r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error { return requireMemoryTenant(*state, tenant) })
}
func (r memoryReleaseCatalogRepository) ReadCatalogCreationProduct(ctx context.Context, tenant, id string) (releaseapp.CatalogCreationProduct, error) {
	if err := r.LockCatalogCreationTenant(ctx, tenant); err != nil {
		return releaseapp.CatalogCreationProduct{}, err
	}
	if id == "" || len(id) > 1024 || !utf8.ValidString(id) || strings.ContainsRune(id, 0) || strings.TrimSpace(id) != id {
		return releaseapp.CatalogCreationProduct{}, ErrValidation
	}
	var v releaseapp.CatalogCreationProduct
	err := r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		p, ok := state.Products[id]
		if !ok || p.TenantID != tenant {
			return ErrNotFound
		}
		v = releaseapp.CatalogCreationProduct{ID: p.ID, TenantID: p.TenantID}
		return nil
	})
	return v, err
}
