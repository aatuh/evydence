package app

import (
	"context"
	"strings"
	"unicode/utf8"

	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

var _ releaseapp.ProductSlugReader = memoryReleaseCatalogRepository{}

func (r memoryReleaseCatalogRepository) ProductSlugExists(ctx context.Context, tenant, slug string) (bool, error) {
	tenant, slug = strings.TrimSpace(tenant), strings.TrimSpace(slug)
	for _, field := range []struct {
		text  string
		limit int
	}{{tenant, 1024}, {slug, 1024}} {
		if field.text == "" || len(field.text) > field.limit || !utf8.ValidString(field.text) || strings.ContainsRune(field.text, 0) {
			return false, ErrValidation
		}
	}
	exists := false
	err := r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := requireMemoryTenant(*state, tenant); err != nil {
			return err
		}
		for _, p := range state.Products {
			if p.TenantID == tenant && p.Slug == slug {
				exists = true
				break
			}
		}
		return nil
	})
	return exists, err
}
