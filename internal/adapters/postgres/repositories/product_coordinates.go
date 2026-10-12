package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

var _ releaseapp.ProductCoordinateReader = releaseCatalog{}

func (r releaseCatalog) ReadProductCoordinates(ctx context.Context, tenant, id string) (releaseapp.ProductCoordinates, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releaseapp.ProductCoordinates{}, err
	}
	// Use the same fence-before-row-lock ordering as other focused writers.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releaseapp.ProductCoordinates{}, err
	}
	var v releaseapp.ProductCoordinates
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(slug,65537),octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(slug)>65536 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&v.ID, &v.TenantID, &v.Slug, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releaseapp.ProductCoordinates{}, app.ErrNotFound
	}
	if err != nil {
		return releaseapp.ProductCoordinates{}, fmt.Errorf("read catalog product coordinates: %w", err)
	}
	if large {
		return releaseapp.ProductCoordinates{}, app.ErrConflict
	}
	return v, nil
}
