package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

var _ releaseapp.ReleaseStateReader = releaseCatalog{}

// ReadReleaseState locks only the selected release after the projection fence.
// Text is bounded in SQL, and overflow is rejected rather than trusted.
func (r releaseCatalog) ReadReleaseState(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releasedomain.Release{}, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releasedomain.Release{}, err
	}
	var v releasedomain.Release
	var state string
	var frozen, approved sql.NullTime
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(r.id,1025),left(r.tenant_id,1025),left(r.product_id,1025),left(r.version,65537),left(r.state,33),r.revision,r.created_at,r.frozen_at,r.approved_at,
 octet_length(r.id)>1024 OR octet_length(r.tenant_id)>1024 OR octet_length(r.product_id)>1024 OR octet_length(r.version)>65536 OR octet_length(r.state)>32
 FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id
 WHERE r.tenant_id=$1 AND r.id=$2 FOR UPDATE OF r`, tenant, id).Scan(&v.ID, &v.TenantID, &v.ProductID, &v.Version, &state, &v.Revision, &v.CreatedAt, &frozen, &approved, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releasedomain.Release{}, app.ErrNotFound
	}
	if err != nil {
		return releasedomain.Release{}, fmt.Errorf("read release transition state: %w", err)
	}
	if large {
		return releasedomain.Release{}, app.ErrConflict
	}
	v.State, err = releasedomain.ParseReleaseState(state)
	if err != nil || v.Revision < 1 || v.CreatedAt.IsZero() {
		return releasedomain.Release{}, app.ErrConflict
	}
	v.CreatedAt = v.CreatedAt.UTC()
	if frozen.Valid {
		at := frozen.Time.UTC()
		v.FrozenAt = &at
	}
	if approved.Valid {
		at := approved.Time.UTC()
		v.ApprovedAt = &at
	}
	return v, nil
}
