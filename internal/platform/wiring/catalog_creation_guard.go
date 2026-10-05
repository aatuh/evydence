package wiring

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type catalogCreationGuard struct {
	reader releaseapp.CatalogCreationGuardReader
}

func (g catalogCreationGuard) LockCatalogCreationTenant(ctx context.Context, tenant string) error {
	return mapProductWriteError(g.reader.LockCatalogCreationTenant(ctx, tenant))
}
func (g catalogCreationGuard) ReadCatalogCreationProduct(ctx context.Context, tenant, id string) (releaseapp.CatalogCreationProduct, error) {
	v, err := g.reader.ReadCatalogCreationProduct(ctx, tenant, id)
	return v, mapProductWriteError(err)
}
func (catalogCreationGuard) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return releasequery.NewCatalogAuthorizer().Authorize(ctx, a, r)
}
