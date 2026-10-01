package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

var _ operationsquery.RetentionReader = (*Store)(nil)

// ReadRetentionRecords reads only the tenant's legal-hold and override rows.
// Both sets come from one repeatable-read snapshot, so a concurrent write
// cannot make the report describe two different committed states.
func (s *Store) ReadRetentionRecords(ctx context.Context, tenantID, scopeType, scopeID string) (operationsquery.RetentionSnapshot, error) {
	var empty operationsquery.RetentionSnapshot
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return empty, operationsquery.ErrValidation
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin retention snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()

	snapshot := operationsquery.RetentionSnapshot{
		LegalHolds:         []operationsdomain.LegalHold{},
		RetentionOverrides: []operationsdomain.RetentionOverride{},
	}
	holds, err := tx.Query(ctx, `
		SELECT id,tenant_id,scope_type,scope_id,reason,owner,released_at,schema_version,created_at
		FROM legal_holds
		WHERE tenant_id=$1 AND ($2='' OR (scope_type=$2 AND scope_id=$3))
		ORDER BY created_at,id`, tenantID, scopeType, scopeID)
	if err != nil {
		return empty, fmt.Errorf("read legal holds: %w", err)
	}
	for holds.Next() {
		var hold operationsdomain.LegalHold
		var releasedAt sql.NullTime
		if err := holds.Scan(&hold.ID, &hold.TenantID, &hold.ScopeType, &hold.ScopeID, &hold.Reason, &hold.Owner, &releasedAt, &hold.SchemaVersion, &hold.CreatedAt); err != nil {
			holds.Close()
			return empty, fmt.Errorf("scan legal hold: %w", err)
		}
		if releasedAt.Valid {
			hold.ReleasedAt = &releasedAt.Time
		}
		snapshot.LegalHolds = append(snapshot.LegalHolds, hold)
	}
	err = holds.Err()
	holds.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate legal holds: %w", err)
	}

	overrides, err := tx.Query(ctx, `
		SELECT id,tenant_id,scope_type,scope_id,retention_until,reason,owner,schema_version,created_at
		FROM retention_overrides
		WHERE tenant_id=$1 AND ($2='' OR (scope_type=$2 AND scope_id=$3))
		ORDER BY created_at,id`, tenantID, scopeType, scopeID)
	if err != nil {
		return empty, fmt.Errorf("read retention overrides: %w", err)
	}
	for overrides.Next() {
		var override operationsdomain.RetentionOverride
		if err := overrides.Scan(&override.ID, &override.TenantID, &override.ScopeType, &override.ScopeID, &override.RetentionUntil, &override.Reason, &override.Owner, &override.SchemaVersion, &override.CreatedAt); err != nil {
			overrides.Close()
			return empty, fmt.Errorf("scan retention override: %w", err)
		}
		snapshot.RetentionOverrides = append(snapshot.RetentionOverrides, override)
	}
	err = overrides.Err()
	overrides.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate retention overrides: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit retention snapshot: %w", err)
	}
	return snapshot, nil
}
