package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func (r integrity) ReadTransparencyCheckpointSource(ctx context.Context, tenant, id string) (verificationapp.TransparencyCheckpointSource, error) {
	s := verificationapp.TransparencyCheckpointSource{TenantID: tenant, ID: id}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return s, err
	}
	// This command appends audit state: acquire the exclusive projection fence
	// before the selected batch lock, avoiding a later read-to-write upgrade.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return s, fmt.Errorf("lock checkpoint projection: %w", err)
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
