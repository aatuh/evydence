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
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

var _ releaseapp.ArtifactRegistrationReader = releaseCatalog{}

func (r releaseCatalog) ArtifactIdentityByDigest(ctx context.Context, tenant, digest string) (releaseapp.ArtifactRegistrationIdentity, bool, error) {
	tenant, digest = strings.TrimSpace(tenant), strings.TrimSpace(digest)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, digest); err != nil {
		return releaseapp.ArtifactRegistrationIdentity{}, false, err
	}
	if len(digest) > 71 {
		return releaseapp.ArtifactRegistrationIdentity{}, false, app.ErrValidation
	}
	// Fence first, then serialize absent digest identity through the tenant
	// row. Private artifact metadata is not selected by this lookup.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releaseapp.ArtifactRegistrationIdentity{}, false, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, tenant); err != nil {
		return releaseapp.ArtifactRegistrationIdentity{}, false, err
	}
	var v releaseapp.ArtifactRegistrationIdentity
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(digest,72),octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(digest)>71 FROM artifacts WHERE tenant_id=$1 AND digest=$2 FOR SHARE`, tenant, digest).Scan(&v.ID, &v.TenantID, &v.Digest, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releaseapp.ArtifactRegistrationIdentity{}, false, nil
	}
	if err := buildIdentityReadError(err, large); err != nil {
		return releaseapp.ArtifactRegistrationIdentity{}, false, err
	}
	return v, true, nil
}

func (r releaseCatalog) ReadArtifactMetadata(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return releasedomain.Artifact{}, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releasedomain.Artifact{}, err
	}
	var v releasedomain.Artifact
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(name,65537),left(media_type,65537),size,left(digest,72),created_at,
 octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(name)>65536 OR octet_length(media_type)>65536 OR octet_length(digest)>71
 FROM artifacts WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&v.ID, &v.TenantID, &v.Name, &v.MediaType, &v.Size, &v.Digest, &v.CreatedAt, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releasedomain.Artifact{}, app.ErrNotFound
	}
	if err != nil {
		return releasedomain.Artifact{}, fmt.Errorf("read artifact registration metadata: %w", err)
	}
	if large {
		return releasedomain.Artifact{}, app.ErrConflict
	}
	v.CreatedAt = v.CreatedAt.UTC()
	return v, nil
}
