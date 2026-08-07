package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// GetObjectPayload loads lifecycle metadata by the tenant-scoped digest. It
// deliberately does not return raw payload bytes or untrusted storage errors.
func (s *Store) GetObjectPayload(ctx context.Context, tenantID, digest string) (app.ObjectPayload, error) {
	if s == nil || s.pool == nil || strings.TrimSpace(tenantID) == "" || !validObjectPayloadDigest(digest) {
		return app.ObjectPayload{}, app.ErrValidation
	}
	payload, err := scanObjectPayload(s.pool.QueryRow(ctx, `
		SELECT tenant_id, digest, size, media_type, staging_key, final_key, status,
			failure_code, created_at, updated_at, finalized_at, failed_at, orphaned_at
		FROM object_payloads
		WHERE tenant_id = $1 AND digest = $2 AND status <> 'orphaned'
	`, strings.TrimSpace(tenantID), digest))
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ObjectPayload{}, app.ErrNotFound
	}
	if err != nil {
		return app.ObjectPayload{}, fmt.Errorf("load object payload lifecycle: %w", err)
	}
	return payload, nil
}

func (s *Store) MarkObjectPayloadFinalized(ctx context.Context, payload app.ObjectPayload) error {
	if s == nil || s.pool == nil || app.ValidateObjectPayloadForRepository(payload) != nil {
		return app.ErrValidation
	}
	result, err := s.pool.Exec(ctx, `
		UPDATE object_payloads
		SET status = 'finalized', failure_code = NULL, finalized_at = now(), failed_at = NULL,
			orphaned_at = NULL, updated_at = now()
		WHERE tenant_id = $1 AND digest = $2 AND final_key = $3
		  AND status IN ('staged', 'failed', 'finalized')
	`, payload.TenantID, payload.Digest, payload.FinalKey)
	if err != nil {
		return fmt.Errorf("mark object payload finalized: %w", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (s *Store) MarkObjectPayloadFailed(ctx context.Context, payload app.ObjectPayload, failureCode string) error {
	if s == nil || s.pool == nil || app.ValidateObjectPayloadForRepository(payload) != nil || !validObjectPayloadFailureCode(failureCode) {
		return app.ErrValidation
	}
	result, err := s.pool.Exec(ctx, `
		UPDATE object_payloads
		SET status = 'failed', failure_code = $4, failed_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND digest = $2 AND final_key = $3
		  AND (status IN ('staged', 'failed') OR (status = 'finalized' AND $4 = 'reconciliation_mismatch'))
	`, payload.TenantID, payload.Digest, payload.FinalKey, failureCode)
	if err != nil {
		return fmt.Errorf("mark object payload failed: %w", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

// ListObjectPayloads returns a tenant-only, bounded reconciliation page. The
// cursor is an offset rather than an object key or digest so worker receipts
// and command output remain free of object identifiers. Repeated pages are
// harmless: lifecycle transitions are idempotent and no list is deletion
// authority.
func (s *Store) ListObjectPayloads(ctx context.Context, tenantID string, cursor, limit int) ([]app.ObjectPayload, int, error) {
	if s == nil || s.pool == nil || strings.TrimSpace(tenantID) == "" || cursor < 0 || limit < 1 || limit > 1_000 {
		return nil, 0, app.ErrValidation
	}
	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id, digest, size, media_type, staging_key, final_key, status,
			failure_code, created_at, updated_at, finalized_at, failed_at, orphaned_at
		FROM object_payloads
		WHERE tenant_id = $1
		ORDER BY created_at ASC, digest ASC, final_key ASC
		OFFSET $2 LIMIT $3
	`, strings.TrimSpace(tenantID), cursor, limit+1)
	if err != nil {
		return nil, 0, fmt.Errorf("list object payloads: %w", err)
	}
	defer rows.Close()
	payloads := make([]app.ObjectPayload, 0, limit)
	for rows.Next() {
		payload, err := scanObjectPayload(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan object payload reconciliation page: %w", err)
		}
		payloads = append(payloads, payload)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate object payload reconciliation page: %w", err)
	}
	nextCursor := 0
	if len(payloads) > limit {
		payloads = payloads[:limit]
		nextCursor = cursor + limit
	}
	return payloads, nextCursor, nil
}

// ObjectPayloadOwnsObject reports database ownership for both staging and
// final keys, including quarantined rows. It is intentionally exact and
// tenant-scoped; provider inventory must never infer ownership across a
// tenant boundary.
func (s *Store) ObjectPayloadOwnsObject(ctx context.Context, tenantID, key string) (bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	key = strings.TrimSpace(key)
	if s == nil || s.pool == nil || tenantID == "" || key == "" || !strings.HasPrefix(key, "tenants/"+tenantID+"/") {
		return false, app.ErrValidation
	}
	var owned bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM object_payloads
			WHERE tenant_id = $1 AND (staging_key = $2 OR final_key = $2)
		)
	`, tenantID, key).Scan(&owned); err != nil {
		return false, fmt.Errorf("check object payload ownership: %w", err)
	}
	return owned, nil
}

// RecordObjectReconciliationReceipt atomically persists safe counters and an
// append-only audit entry. Neither record includes raw bytes, provider errors,
// object paths, or digests.
func (s *Store) RecordObjectReconciliationReceipt(ctx context.Context, receipt app.ObjectReconciliationReceipt) error {
	if s == nil || s.pool == nil || !validObjectReconciliationReceipt(receipt) {
		return app.ErrValidation
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin object reconciliation receipt transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var tenantExists int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM tenants WHERE id = $1`, receipt.TenantID).Scan(&tenantExists); err != nil {
		return fmt.Errorf("verify object reconciliation tenant: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO object_reconciliation_receipts (
			id, schema_version, tenant_id, dry_run, metadata_cursor, next_metadata_cursor,
			provider_cursor, next_provider_cursor, scanned_payloads,
			healthy_payloads, missing_final_objects, missing_staged_objects,
			digest_mismatches, recovered_finalizations, abandoned_staging,
			provider_orphans, quarantined_payloads, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`, receipt.ID, receipt.SchemaVersion, receipt.TenantID, receipt.DryRun, receipt.MetadataCursor, nullableReconciliationCursor(receipt.NextMetadataCursor), receipt.ProviderCursor, nullableReconciliationCursor(receipt.NextProviderCursor), receipt.ScannedPayloads, receipt.HealthyPayloads, receipt.MissingFinalObjects, receipt.MissingStagedObjects, receipt.DigestMismatches, receipt.RecoveredFinalizations, receipt.AbandonedStaging, receipt.ProviderOrphans, receipt.QuarantinedPayloads, receipt.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("insert object reconciliation receipt: %w", err)
	}
	_, err = repositories.New(tx).Audit.Append(ctx, domain.AuditChainEntry{
		ID:          "ace_" + receipt.ID,
		TenantID:    receipt.TenantID,
		EntryType:   "object_payload.reconciled",
		SubjectType: "object_reconciliation",
		SubjectID:   receipt.ID,
		ActorType:   "worker",
		ActorID:     "evydence-worker",
		OccurredAt:  receipt.CreatedAt.UTC(),
		Metadata: map[string]any{
			"dry_run":                 receipt.DryRun,
			"scanned_payloads":        receipt.ScannedPayloads,
			"missing_final_objects":   receipt.MissingFinalObjects,
			"missing_staged_objects":  receipt.MissingStagedObjects,
			"digest_mismatches":       receipt.DigestMismatches,
			"recovered_finalizations": receipt.RecoveredFinalizations,
			"abandoned_staging":       receipt.AbandonedStaging,
			"provider_orphans":        receipt.ProviderOrphans,
			"quarantined_payloads":    receipt.QuarantinedPayloads,
		},
	})
	if err != nil {
		return fmt.Errorf("append object reconciliation audit entry: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit object reconciliation receipt transaction: %w", err)
	}
	return nil
}

// ObjectReconciliationMetrics reads tenant-scoped, receipt-backed counters
// suitable for API metrics. The values have no raw object identifiers.
func (s *Store) ObjectReconciliationMetrics(ctx context.Context, tenantID string) (app.ObjectReconciliationMetrics, error) {
	tenantID = strings.TrimSpace(tenantID)
	if s == nil || s.pool == nil || tenantID == "" {
		return app.ObjectReconciliationMetrics{}, app.ErrValidation
	}
	var metrics app.ObjectReconciliationMetrics
	var lastRun sql.NullTime
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*),
			COALESCE(SUM(scanned_payloads), 0),
			COALESCE(SUM(missing_final_objects), 0),
			COALESCE(SUM(missing_staged_objects), 0),
			COALESCE(SUM(digest_mismatches), 0),
			COALESCE(SUM(provider_orphans), 0),
			COALESCE(SUM(quarantined_payloads), 0),
			MAX(created_at)
		FROM object_reconciliation_receipts
		WHERE tenant_id = $1
	`, tenantID).Scan(&metrics.Runs, &metrics.ScannedPayloads, &metrics.MissingFinalObjects, &metrics.MissingStagedObjects, &metrics.DigestMismatches, &metrics.ProviderOrphans, &metrics.QuarantinedPayloads, &lastRun); err != nil {
		return app.ObjectReconciliationMetrics{}, fmt.Errorf("read object reconciliation metrics: %w", err)
	}
	if lastRun.Valid {
		metrics.LastRunAt = lastRun.Time.UTC()
	}
	return metrics, nil
}

func (s *Store) MarkObjectPayloadOrphaned(ctx context.Context, payload app.ObjectPayload) error {
	if s == nil || s.pool == nil || app.ValidateObjectPayloadForRepository(payload) != nil {
		return app.ErrValidation
	}
	result, err := s.pool.Exec(ctx, `
		UPDATE object_payloads
		SET status = 'orphaned', failure_code = 'object_missing', orphaned_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND digest = $2 AND final_key = $3
	`, payload.TenantID, payload.Digest, payload.FinalKey)
	if err != nil {
		return fmt.Errorf("mark object payload orphaned: %w", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

type objectPayloadRow interface {
	Scan(...any) error
}

func scanObjectPayload(row objectPayloadRow) (app.ObjectPayload, error) {
	var payload app.ObjectPayload
	var mediaType, failureCode sql.NullString
	var finalizedAt, failedAt, orphanedAt sql.NullTime
	var status string
	if err := row.Scan(
		&payload.TenantID, &payload.Digest, &payload.Size, &mediaType, &payload.StagingKey, &payload.FinalKey, &status,
		&failureCode, &payload.CreatedAt, &payload.UpdatedAt, &finalizedAt, &failedAt, &orphanedAt,
	); err != nil {
		return app.ObjectPayload{}, err
	}
	payload.MediaType = mediaType.String
	payload.FailureCode = failureCode.String
	payload.Status = app.ObjectPayloadStatus(status)
	payload.FinalizedAt = nullableObjectPayloadTime(finalizedAt)
	payload.FailedAt = nullableObjectPayloadTime(failedAt)
	payload.OrphanedAt = nullableObjectPayloadTime(orphanedAt)
	if err := app.ValidateObjectPayloadForRepository(payload); err != nil {
		return app.ObjectPayload{}, app.ErrValidation
	}
	return payload, nil
}

func nullableObjectPayloadTime(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	copy := value.Time.UTC()
	return &copy
}

func validObjectPayloadDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(strings.TrimPrefix(value, "sha256:")) == 64
}

func validObjectPayloadFailureCode(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 96 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func validObjectReconciliationReceipt(receipt app.ObjectReconciliationReceipt) bool {
	if strings.TrimSpace(receipt.ID) == "" || receipt.SchemaVersion != app.ObjectReconciliationReceiptSchemaVersion || strings.TrimSpace(receipt.TenantID) == "" || receipt.CreatedAt.IsZero() || receipt.MetadataCursor < 0 || receipt.NextMetadataCursor < 0 || receipt.ProviderCursor < 0 || receipt.NextProviderCursor < 0 {
		return false
	}
	return receipt.ScannedPayloads >= 0 && receipt.HealthyPayloads >= 0 && receipt.MissingFinalObjects >= 0 && receipt.MissingStagedObjects >= 0 && receipt.DigestMismatches >= 0 && receipt.RecoveredFinalizations >= 0 && receipt.AbandonedStaging >= 0 && receipt.ProviderOrphans >= 0 && receipt.QuarantinedPayloads >= 0
}

func nullableReconciliationCursor(value int) any {
	if value == 0 {
		return nil
	}
	return value
}
