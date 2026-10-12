package app

import (
	"context"
	"strings"
	"unicode/utf8"

	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

var _ releaseapp.ReleaseVersionReader = memoryReleaseCatalogRepository{}

func (r memoryReleaseCatalogRepository) ReleaseVersionExists(ctx context.Context, tenant, product, version string) (bool, error) {
	if _, err := r.ReadProductCoordinates(ctx, tenant, product); err != nil {
		return false, err
	}
	version = strings.TrimSpace(version)
	if version == "" || len(version) > 65536 || !utf8.ValidString(version) || strings.ContainsRune(version, 0) {
		return false, ErrValidation
	}
	var exists bool
	err := r.uow.mutate(ctx, func(state *MemoryUnitOfWorkSnapshot) error {
		for _, v := range state.Releases {
			if v.TenantID == strings.TrimSpace(tenant) && v.ProductID == strings.TrimSpace(product) && v.Version == version {
				exists = true
				break
			}
		}
		return nil
	})
	return exists, err
}
