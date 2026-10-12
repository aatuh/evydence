package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	releasequery "github.com/aatuh/evydence/internal/release/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func (r supplyChain) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	return ReadArtifactGrant(ctx, r.tx, request)
}

func (r supplyChain) LockSignatureArtifact(ctx context.Context, tenant, id string) (verificationapp.SignatureArtifact, error) {
	if _, err := r.LockArtifactSignatureCreationScope(ctx, tenant, id); err != nil {
		return verificationapp.SignatureArtifact{}, err
	}
	var a verificationapp.SignatureArtifact
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(digest,1025),octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(digest)>1024 FROM artifacts WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&a.ID, &a.TenantID, &a.Digest, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, app.ErrNotFound
	}
	if err != nil {
		return a, fmt.Errorf("lock signature artifact: %w", err)
	}
	if large {
		return verificationapp.SignatureArtifact{}, app.ErrConflict
	}
	return a, nil
}

func (r supplyChain) LockArtifactSignatureCreationScope(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	var refs application.ResourceReferences
	if ctx == nil || r.tx == nil || !validRetentionCoordinate(tenant) || !validRetentionCoordinate(id) {
		return refs, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return refs, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return refs, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return refs, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM artifacts WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id); err != nil {
		return refs, err
	}
	return application.ResourceReferences{ArtifactID: id}, nil
}
