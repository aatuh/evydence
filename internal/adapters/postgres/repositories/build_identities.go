package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releaseapp.BuildIdentityReader = releaseCatalog{}

func (r releaseCatalog) ReadBuildArtifactGrant(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	return ReadArtifactGrant(ctx, r.tx, request)
}

type buildIdentityQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func validBuildIdentityRead(ctx context.Context, q buildIdentityQueryer, tenant, id string) error {
	if ctx == nil || q == nil {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, v := range []string{tenant, id} {
		if v == "" || len(v) > 1024 || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return app.ErrValidation
		}
	}
	return nil
}
func buildIdentityReadError(err error, large bool) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read build coordinates: %w", err)
	}
	if large {
		return app.ErrConflict
	}
	return nil
}
func ReadBuildProject(ctx context.Context, q buildIdentityQueryer, tenant, id string, lock bool) (releasedomain.Project, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if err := validBuildIdentityRead(ctx, q, tenant, id); err != nil {
		return releasedomain.Project{}, err
	}
	var v releasedomain.Project
	var large bool
	sql := `SELECT left(j.id,1025),left(j.tenant_id,1025),left(j.product_id,1025),octet_length(j.id)>1024 OR octet_length(j.tenant_id)>1024 OR octet_length(j.product_id)>1024 FROM projects j JOIN products p ON p.id=j.product_id AND p.tenant_id=j.tenant_id WHERE j.tenant_id=$1 AND j.id=$2`
	if lock {
		sql += ` FOR SHARE OF j,p`
	}
	err := q.QueryRow(ctx, sql, tenant, id).Scan(&v.ID, &v.TenantID, &v.ProductID, &large)
	if err := buildIdentityReadError(err, large); err != nil {
		return releasedomain.Project{}, err
	}
	return v, nil
}
func ReadBuildRelease(ctx context.Context, q buildIdentityQueryer, tenant, id string, lock bool) (releasedomain.Release, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if err := validBuildIdentityRead(ctx, q, tenant, id); err != nil {
		return releasedomain.Release{}, err
	}
	var v releasedomain.Release
	var large bool
	sql := `SELECT left(r.id,1025),left(r.tenant_id,1025),left(r.product_id,1025),left(r.version,65537),octet_length(r.id)>1024 OR octet_length(r.tenant_id)>1024 OR octet_length(r.product_id)>1024 OR octet_length(r.version)>65536 FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.id=$2`
	if lock {
		sql += ` FOR SHARE OF r,p`
	}
	err := q.QueryRow(ctx, sql, tenant, id).Scan(&v.ID, &v.TenantID, &v.ProductID, &v.Version, &large)
	if err := buildIdentityReadError(err, large); err != nil {
		return releasedomain.Release{}, err
	}
	return v, nil
}
func ReadBuildArtifact(ctx context.Context, q buildIdentityQueryer, tenant, id string, lock bool) (releasedomain.Artifact, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if err := validBuildIdentityRead(ctx, q, tenant, id); err != nil {
		return releasedomain.Artifact{}, err
	}
	var v releasedomain.Artifact
	var large bool
	sql := `SELECT left(id,1025),left(tenant_id,1025),left(digest,72),octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(digest)>71 FROM artifacts WHERE tenant_id=$1 AND id=$2`
	if lock {
		sql += ` FOR SHARE`
	}
	err := q.QueryRow(ctx, sql, tenant, id).Scan(&v.ID, &v.TenantID, &v.Digest, &large)
	if err := buildIdentityReadError(err, large); err != nil {
		return releasedomain.Artifact{}, err
	}
	return v, nil
}
func (r releaseCatalog) ReadBuildProject(ctx context.Context, tenant, id string) (releasedomain.Project, error) {
	if err := validBuildIdentityRead(ctx, r.tx, strings.TrimSpace(tenant), strings.TrimSpace(id)); err != nil {
		return releasedomain.Project{}, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, strings.TrimSpace(tenant)); err != nil {
		return releasedomain.Project{}, err
	}
	return ReadBuildProject(ctx, r.tx, tenant, id, true)
}
func (r releaseCatalog) ReadBuildRelease(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	if err := validBuildIdentityRead(ctx, r.tx, strings.TrimSpace(tenant), strings.TrimSpace(id)); err != nil {
		return releasedomain.Release{}, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, strings.TrimSpace(tenant)); err != nil {
		return releasedomain.Release{}, err
	}
	return ReadBuildRelease(ctx, r.tx, tenant, id, true)
}
func (r releaseCatalog) ReadBuildArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	if err := validBuildIdentityRead(ctx, r.tx, strings.TrimSpace(tenant), strings.TrimSpace(id)); err != nil {
		return releasedomain.Artifact{}, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, strings.TrimSpace(tenant)); err != nil {
		return releasedomain.Artifact{}, err
	}
	return ReadBuildArtifact(ctx, r.tx, tenant, id, true)
}
