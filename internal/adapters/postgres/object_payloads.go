package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
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
		  AND status IN ('staged', 'failed')
	`, payload.TenantID, payload.Digest, payload.FinalKey, failureCode)
	if err != nil {
		return fmt.Errorf("mark object payload failed: %w", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
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
