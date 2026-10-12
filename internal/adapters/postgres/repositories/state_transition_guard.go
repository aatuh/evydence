package repositories

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func (r releaseCatalog) ReadReleaseTransitionScope(ctx context.Context, tenant, id string) (releaseapp.ReleaseTransitionScope, error) {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releaseapp.ReleaseTransitionScope{}, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releaseapp.ReleaseTransitionScope{}, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return releaseapp.ReleaseTransitionScope{}, err
	}
	var v releaseapp.ReleaseTransitionScope
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(r.id,1025),left(r.tenant_id,1025),left(p.id,1025),octet_length(r.id)>1024 OR octet_length(r.tenant_id)>1024 OR octet_length(p.id)>1024 FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.id=$2 FOR SHARE OF r,p`, tenant, id).Scan(&v.ID, &v.TenantID, &v.ProductID, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releaseapp.ReleaseTransitionScope{}, app.ErrNotFound
	}
	if err := buildIdentityReadError(err, large); err != nil {
		return releaseapp.ReleaseTransitionScope{}, err
	}
	return v, nil
}
func (r releaseCatalog) ReadCandidateTransitionScope(ctx context.Context, tenant, id string) (releaseapp.CandidateTransitionScope, error) {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releaseapp.CandidateTransitionScope{}, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releaseapp.CandidateTransitionScope{}, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return releaseapp.CandidateTransitionScope{}, err
	}
	var v releaseapp.CandidateTransitionScope
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(c.id,1025),left(c.tenant_id,1025),left(r.id,1025),left(p.id,1025),octet_length(c.id)>1024 OR octet_length(c.tenant_id)>1024 OR octet_length(r.id)>1024 OR octet_length(p.id)>1024 FROM release_candidates c JOIN releases r ON r.id=c.release_id AND r.tenant_id=c.tenant_id JOIN products p ON p.id=r.product_id AND p.tenant_id=c.tenant_id WHERE c.tenant_id=$1 AND c.id=$2 FOR SHARE OF c,r,p`, tenant, id).Scan(&v.ID, &v.TenantID, &v.ReleaseID, &v.ProductID, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releaseapp.CandidateTransitionScope{}, app.ErrNotFound
	}
	if err := buildIdentityReadError(err, large); err != nil {
		return releaseapp.CandidateTransitionScope{}, err
	}
	return v, nil
}
