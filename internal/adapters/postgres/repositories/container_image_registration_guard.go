package repositories

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func (r supplyChain) ContainerImageRegistrationIdentityByKey(ctx context.Context, tenant, repository, digest string) (releaseapp.ContainerImageRegistrationIdentity, bool, error) {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, digest); err != nil {
		return releaseapp.ContainerImageRegistrationIdentity{}, false, err
	}
	if repository == "" || len(repository) > 65536 || len(digest) > 71 || !utf8.ValidString(repository) || strings.ContainsRune(repository, 0) {
		return releaseapp.ContainerImageRegistrationIdentity{}, false, app.ErrValidation
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return releaseapp.ContainerImageRegistrationIdentity{}, false, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, tenant); err != nil {
		return releaseapp.ContainerImageRegistrationIdentity{}, false, err
	}
	var v releaseapp.ContainerImageRegistrationIdentity
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(COALESCE(artifact_id,''),1025),octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR COALESCE(octet_length(artifact_id),0)>1024 FROM container_images WHERE tenant_id=$1 AND repository=$2 AND digest=$3 FOR SHARE`, tenant, repository, digest).Scan(&v.ID, &v.TenantID, &v.ArtifactID, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return releaseapp.ContainerImageRegistrationIdentity{}, false, nil
	}
	if err := buildIdentityReadError(err, large); err != nil {
		return releaseapp.ContainerImageRegistrationIdentity{}, false, err
	}
	return v, true, nil
}
