package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func (r deployments) LockEnvironmentProduct(ctx context.Context, tenant, id string) (operationsapp.EnvironmentProduct, error) {
	var p operationsapp.EnvironmentProduct
	// Serialize name-level reuse even when no environment exists yet. The
	// product lock permits tenant/product foreign-key readers and avoids
	// loading product metadata or unrelated environment rows.
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025) FROM products WHERE tenant_id=$1 AND id=$2 FOR NO KEY UPDATE`, tenant, id).Scan(&p.ID, &p.TenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, app.ErrNotFound
	}
	if err != nil {
		return p, fmt.Errorf("lock environment product: %w", err)
	}
	if len(p.ID) > 1024 || len(p.TenantID) > 1024 {
		return operationsapp.EnvironmentProduct{}, app.ErrConflict
	}
	return p, nil
}
func (r deployments) EnvironmentByName(ctx context.Context, tenant, product, name string) (operationsdomain.DeploymentEnvironment, bool, error) {
	var v operationsdomain.DeploymentEnvironment
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(product_id,1025),left(name,65537),left(kind,65537),left(schema_version,1025),created_at,
 octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(product_id)>1024 OR octet_length(name)>65536 OR octet_length(kind)>65536 OR octet_length(schema_version)>1024
 FROM deployment_environments WHERE tenant_id=$1 AND product_id=$2 AND name=$3 FOR SHARE`, tenant, product, name).Scan(&v.ID, &v.TenantID, &v.ProductID, &v.Name, &v.Kind, &v.SchemaVersion, &v.CreatedAt, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, false, nil
	}
	if err != nil {
		return v, false, fmt.Errorf("read named environment: %w", err)
	}
	if large {
		return operationsdomain.DeploymentEnvironment{}, false, app.ErrConflict
	}
	return v, true, nil
}
