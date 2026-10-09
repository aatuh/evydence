package app

import (
	"context"
	"strings"
	"unicode/utf8"

	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

var _ releaseapp.ProductCoordinateReader = memoryReleaseCatalogRepository{}

func (r memoryReleaseCatalogRepository) ReadProductCoordinates(ctx context.Context, tenant, id string) (releaseapp.ProductCoordinates, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	for _, text := range []string{tenant, id} {
		if text == "" || len(text) > 1024 || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return releaseapp.ProductCoordinates{}, ErrValidation
		}
	}
	var v releaseapp.ProductCoordinates
	err := r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		p, ok := state.Products[id]
		if !ok || p.TenantID != tenant {
			return ErrNotFound
		}
		if len(p.ID) > 1024 || len(p.TenantID) > 1024 || len(p.Slug) > 65536 {
			return ErrConflict
		}
		v = releaseapp.ProductCoordinates{ID: p.ID, TenantID: p.TenantID, Slug: p.Slug}
		return nil
	})
	return v, err
}
