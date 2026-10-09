package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func (r integrity) lockTransparencyCheckpointTenant(ctx context.Context, tenant, id string) error {
	_, tenantErr := verificationapp.NormalizeSigningKeyID(tenant)
	_, idErr := verificationapp.NormalizeSigningKeyID(id)
	if ctx == nil || r.tx == nil || tenantErr != nil || idErr != nil || strings.TrimSpace(tenant) != tenant || strings.TrimSpace(id) != id {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// All entry points take the common fence before tenant and batch locks.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return fmt.Errorf("lock checkpoint projection: %w", err)
	}
	return requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant)
}

func (r integrity) LockTransparencyCheckpointScope(ctx context.Context, tenant, id string) error {
	if err := r.lockTransparencyCheckpointTenant(ctx, tenant, id); err != nil {
		return err
	}
	return requireRow(ctx, r.tx, `SELECT 1 FROM merkle_batches WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id)
}

func (r integrity) ReadTransparencyCheckpointSource(ctx context.Context, tenant, id string) (verificationapp.TransparencyCheckpointSource, error) {
	s := verificationapp.TransparencyCheckpointSource{TenantID: tenant, ID: id}
	if err := r.lockTransparencyCheckpointTenant(ctx, tenant, id); err != nil {
		return s, err
	}
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT left(root_hash,1025),octet_length(root_hash)>1024 FROM merkle_batches WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&s.RootHash, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, app.ErrNotFound
	}
	if err != nil {
		return s, fmt.Errorf("read checkpoint batch root: %w", err)
	}
	if oversized {
		return s, app.ErrConflict
	}
	return s, nil
}
