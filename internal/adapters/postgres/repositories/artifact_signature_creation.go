package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	releasequery "github.com/aatuh/evydence/internal/release/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func (r supplyChain) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	return ReadArtifactGrant(ctx, r.tx, request)
}

func (r supplyChain) LockSignatureArtifact(ctx context.Context, tenant, id string) (verificationapp.SignatureArtifact, error) {
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
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
