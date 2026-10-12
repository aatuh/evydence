package coordination

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

const workerProjectionAdvisoryNamespace int32 = 0x65767970

// LockWorkerProjection holds the tenant's exclusive projection fence until the
// transaction ends. Every transaction that can change worker projections or
// append audit entries must acquire this before the audit-chain lock.
func LockWorkerProjection(ctx context.Context, tx pgx.Tx, tenantID string) error {
	return lockWorkerProjection(ctx, tx, tenantID, false)
}

// LockWorkerProjectionShared holds a read fence until the transaction ends.
// It is only appropriate for transactions that will not append audit entries.
func LockWorkerProjectionShared(ctx context.Context, tx pgx.Tx, tenantID string) error {
	return lockWorkerProjection(ctx, tx, tenantID, true)
}

func lockWorkerProjection(ctx context.Context, tx pgx.Tx, tenantID string, shared bool) error {
	if ctx == nil || tx == nil || strings.TrimSpace(tenantID) == "" {
		return errors.New("invalid worker projection lock boundary")
	}
	tenantID = strings.TrimSpace(tenantID)
	query := `SELECT pg_advisory_xact_lock($1, hashtext($2))`
	if shared {
		query = `SELECT pg_advisory_xact_lock_shared($1, hashtext($2))`
	}
	_, err := tx.Exec(ctx, query, workerProjectionAdvisoryNamespace, tenantID)
	return err
}
