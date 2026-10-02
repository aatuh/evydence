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
)

var _ releaseapp.ContainerImageIdentityReader = supplyChain{}

func (r supplyChain) ContainerImageByRepositoryDigest(ctx context.Context, tenant, repository, digest string) (releasedomain.ContainerImage, bool, error) {
	tenant, repository, digest = strings.TrimSpace(tenant), strings.TrimSpace(repository), strings.TrimSpace(digest)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, digest); err != nil {
		return releasedomain.ContainerImage{}, false, err
	}
	if repository == "" || len(repository) > 65536 || digest == "" || len(digest) > 71 || !utf8.ValidString(repository) || strings.ContainsRune(repository, 0) || strings.ContainsRune(digest, 0) {
		return releasedomain.ContainerImage{}, false, app.ErrValidation
	}
	// The worker fence precedes every relational lock. The tenant lock
	// serializes absent-row reuse without relying on a process-wide mutex.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releasedomain.ContainerImage{}, false, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, tenant); err != nil {
		return releasedomain.ContainerImage{}, false, err
	}
	var v releasedomain.ContainerImage
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(COALESCE(artifact_id,''),1025),left(repository,65537),left(COALESCE(tag,''),65537),left(digest,72),left(COALESCE(platform,''),65537),left(schema_version,1025),created_at,
 octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR COALESCE(octet_length(artifact_id),0)>1024 OR octet_length(repository)>65536 OR COALESCE(octet_length(tag),0)>65536 OR octet_length(digest)>71 OR COALESCE(octet_length(platform),0)>65536 OR octet_length(schema_version)>1024
 FROM container_images WHERE tenant_id=$1 AND repository=$2 AND digest=$3 FOR SHARE`, tenant, repository, digest).Scan(&v.ID, &v.TenantID, &v.ArtifactID, &v.Repository, &v.Tag, &v.Digest, &v.Platform, &v.SchemaVersion, &v.CreatedAt, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releasedomain.ContainerImage{}, false, nil
	}
	if err != nil {
		return releasedomain.ContainerImage{}, false, fmt.Errorf("read container image identity: %w", err)
	}
	if large {
		return releasedomain.ContainerImage{}, false, app.ErrConflict
	}
	v.CreatedAt = v.CreatedAt.UTC()
	return v, true, nil
}
