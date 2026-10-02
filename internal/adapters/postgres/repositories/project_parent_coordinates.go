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

var _ releaseapp.ProjectReader = releaseCatalog{}

func (r releaseCatalog) ReadProjectProductCoordinates(ctx context.Context, tenant, id string) (releaseapp.ProjectProductCoordinates, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releaseapp.ProjectProductCoordinates{}, err
	}
	// Use the same fence-before-row-lock ordering as other focused writers.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releaseapp.ProjectProductCoordinates{}, err
	}
	var v releaseapp.ProjectProductCoordinates
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(slug,65537),octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(slug)>65536 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&v.ID, &v.TenantID, &v.Slug, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releaseapp.ProjectProductCoordinates{}, app.ErrNotFound
	}
	if err != nil {
		return releaseapp.ProjectProductCoordinates{}, fmt.Errorf("read project parent coordinates: %w", err)
	}
	if large {
		return releaseapp.ProjectProductCoordinates{}, app.ErrConflict
	}
	return v, nil
}
