package repositories

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func (r releaseCatalog) lockBuildCreationTenant(ctx context.Context, tenant string) error {
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

func (r releaseCatalog) ReadBuildCreationScope(ctx context.Context, tenant, project, release string) (releaseapp.BuildCreationCoordinates, error) {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, project); err != nil {
		return releaseapp.BuildCreationCoordinates{}, err
	}
	if err := validBuildIdentityRead(ctx, r.tx, tenant, release); err != nil {
		return releaseapp.BuildCreationCoordinates{}, err
	}
	if err := r.lockBuildCreationTenant(ctx, tenant); err != nil {
		return releaseapp.BuildCreationCoordinates{}, err
	}
	var v releaseapp.BuildCreationCoordinates
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(j.tenant_id,1025),left(j.id,1025),left(j.product_id,1025),left(r.id,1025),left(r.product_id,1025),octet_length(j.tenant_id)>1024 OR octet_length(j.id)>1024 OR octet_length(j.product_id)>1024 OR octet_length(r.id)>1024 OR octet_length(r.product_id)>1024 FROM projects j JOIN products p ON p.id=j.product_id AND p.tenant_id=j.tenant_id JOIN releases r ON r.tenant_id=j.tenant_id AND r.id=$3 JOIN products rp ON rp.id=r.product_id AND rp.tenant_id=r.tenant_id WHERE j.tenant_id=$1 AND j.id=$2 FOR SHARE OF j,p,r,rp`, tenant, project, release).Scan(&v.TenantID, &v.ProjectID, &v.ProductID, &v.ReleaseID, &v.ReleaseProductID, &large)
	if err := buildIdentityReadError(err, large); err != nil {
		return releaseapp.BuildCreationCoordinates{}, err
	}
	return v, nil
}

func (r releaseCatalog) ReadBuildCreationArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releasedomain.Artifact{}, err
	}
	if err := r.lockBuildCreationTenant(ctx, tenant); err != nil {
		return releasedomain.Artifact{}, err
	}
	var v releasedomain.Artifact
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),octet_length(id)>1024 OR octet_length(tenant_id)>1024 FROM artifacts WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&v.ID, &v.TenantID, &large)
	if err := buildIdentityReadError(err, large); err != nil {
		return releasedomain.Artifact{}, err
	}
	return v, nil
}
