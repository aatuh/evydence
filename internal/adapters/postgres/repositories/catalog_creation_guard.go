package repositories

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func (r releaseCatalog) LockCatalogCreationTenant(ctx context.Context, tenant string) error {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, tenant); err != nil {
		return err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return err
	}
	var one int
	err := r.tx.QueryRow(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	return err
}

func (r releaseCatalog) ReadCatalogCreationProduct(ctx context.Context, tenant, id string) (releaseapp.CatalogCreationProduct, error) {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releaseapp.CatalogCreationProduct{}, err
	}
	if err := r.LockCatalogCreationTenant(ctx, tenant); err != nil {
		return releaseapp.CatalogCreationProduct{}, err
	}
	var p releaseapp.CatalogCreationProduct
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),octet_length(id)>1024 OR octet_length(tenant_id)>1024 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&p.ID, &p.TenantID, &large)
	if err := buildIdentityReadError(err, large); err != nil {
		return releaseapp.CatalogCreationProduct{}, err
	}
	return p, nil
}
