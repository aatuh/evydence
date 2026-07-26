package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
)

type idempotency struct{ tx pgx.Tx }

func (r idempotency) Insert(ctx context.Context, key app.IdempotencyRecordKey, record app.IdempotencyRecord) error {
	if err := app.ValidateIdempotencyKey(key); err != nil {
		return err
	}
	normalized, err := app.NormalizeLegacyIdempotencyRecord(record)
	if err != nil {
		return err
	}
	if err := requireTenant(ctx, r.tx, key.TenantID); err != nil {
		return err
	}
	response, err := json.Marshal(normalized.Response)
	if err != nil {
		return fmt.Errorf("encode idempotency response: %w", err)
	}
	result, err := r.tx.Exec(ctx, `
		INSERT INTO idempotency_records (
			tenant_id, actor_key_id, method, path, idempotency_key,
			request_hash, state, owner_token_hash, status, response,
			created_at, updated_at, lease_expires_at, completed_at, failed_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, 'completed', '', $7, $8, $9, $10, NULL, $11, NULL, $12)
		ON CONFLICT DO NOTHING
	`, key.TenantID, key.ActorID, key.Method, key.Path, key.IdempotencyKey,
		normalized.RequestHash, normalized.Status, response, normalized.CreatedAt, normalized.UpdatedAt,
		normalized.CompletedAt, normalized.ExpiresAt)
	if err != nil {
		return writeError("insert idempotency record", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r idempotency) Reserve(ctx context.Context, reservation app.IdempotencyReservation) (app.IdempotencyReservationResult, error) {
	if err := app.ValidateIdempotencyReservation(reservation); err != nil {
		return app.IdempotencyReservationResult{}, err
	}
	if err := requireTenant(ctx, r.tx, reservation.Key.TenantID); err != nil {
		return app.IdempotencyReservationResult{}, err
	}
	pending := app.PendingIdempotencyRecord(reservation)
	row := r.tx.QueryRow(ctx, `
		INSERT INTO idempotency_records (
			tenant_id, actor_key_id, method, path, idempotency_key,
			request_hash, state, owner_token_hash, status, response,
			created_at, updated_at, lease_expires_at, completed_at, failed_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, 0, 'null'::jsonb, $8, $8, $9, NULL, NULL, $10)
		ON CONFLICT DO NOTHING
		RETURNING request_hash, state, owner_token_hash, status, response, created_at, updated_at, lease_expires_at, completed_at, failed_at, expires_at
	`, reservation.Key.TenantID, reservation.Key.ActorID, reservation.Key.Method, reservation.Key.Path, reservation.Key.IdempotencyKey,
		reservation.RequestHash, reservation.OwnerTokenHash, reservation.Now, reservation.LeaseExpiresAt, reservation.ExpiresAt)
	inserted, err := scanIdempotencyRecord(row)
	if err == nil {
		return app.IdempotencyReservationResult{Outcome: app.IdempotencyReservationAcquired, Record: inserted}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return app.IdempotencyReservationResult{}, fmt.Errorf("reserve idempotency record: %w", err)
	}

	row = r.tx.QueryRow(ctx, `
		SELECT request_hash, state, owner_token_hash, status, response,
		       created_at, updated_at, lease_expires_at, completed_at, failed_at, expires_at
		FROM idempotency_records
		WHERE tenant_id = $1 AND actor_key_id = $2 AND method = $3 AND path = $4 AND idempotency_key = $5
		FOR UPDATE
	`, reservation.Key.TenantID, reservation.Key.ActorID, reservation.Key.Method, reservation.Key.Path, reservation.Key.IdempotencyKey)
	record, err := scanIdempotencyRecord(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return app.IdempotencyReservationResult{}, app.ErrConflict
		}
		return app.IdempotencyReservationResult{}, fmt.Errorf("lock idempotency record: %w", err)
	}
	if !record.ExpiresAt.After(reservation.Now) {
		if err := r.replaceExpired(ctx, reservation); err != nil {
			return app.IdempotencyReservationResult{}, err
		}
		return app.IdempotencyReservationResult{Outcome: app.IdempotencyReservationAcquired, Record: pending}, nil
	}
	if record.RequestHash != reservation.RequestHash {
		return app.IdempotencyReservationResult{}, app.ErrIdempotencyConflict
	}
	switch record.State {
	case app.IdempotencyCompleted:
		return app.IdempotencyReservationResult{Outcome: app.IdempotencyReservationReplay, Record: record}, nil
	case app.IdempotencyFailed:
		return app.IdempotencyReservationResult{Outcome: app.IdempotencyReservationFailure, Record: record}, nil
	case app.IdempotencyPending:
		if record.LeaseExpiresAt != nil && record.LeaseExpiresAt.After(reservation.Now) {
			return app.IdempotencyReservationResult{Outcome: app.IdempotencyReservationPending, Record: record}, nil
		}
		if err := r.recoverPending(ctx, reservation); err != nil {
			return app.IdempotencyReservationResult{}, err
		}
		return app.IdempotencyReservationResult{Outcome: app.IdempotencyReservationRecovered, Record: app.RecoveredPendingIdempotencyRecord(record, reservation)}, nil
	default:
		return app.IdempotencyReservationResult{}, app.ErrValidation
	}
}

func (r idempotency) Complete(ctx context.Context, key app.IdempotencyRecordKey, ownerTokenHash string, status int, response any, now time.Time) error {
	if err := app.ValidateIdempotencyKey(key); err != nil || ownerTokenHash == "" || status < 100 || status > 599 || now.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, key.TenantID); err != nil {
		return err
	}
	responseBody, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("encode completed idempotency response: %w", err)
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE idempotency_records
		SET state = 'completed', owner_token_hash = '', status = $7, response = $8,
		    updated_at = $9, lease_expires_at = NULL, completed_at = $9, failed_at = NULL
		WHERE tenant_id = $1 AND actor_key_id = $2 AND method = $3 AND path = $4 AND idempotency_key = $5
		  AND state = 'pending' AND owner_token_hash = $6
	`, key.TenantID, key.ActorID, key.Method, key.Path, key.IdempotencyKey, ownerTokenHash, status, responseBody, now.UTC())
	if err != nil {
		return writeError("complete idempotency record", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r idempotency) Fail(ctx context.Context, key app.IdempotencyRecordKey, ownerTokenHash string, now time.Time) error {
	if err := app.ValidateIdempotencyKey(key); err != nil || ownerTokenHash == "" || now.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, key.TenantID); err != nil {
		return err
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE idempotency_records
		SET state = 'failed', owner_token_hash = '', status = 0, response = 'null'::jsonb,
		    updated_at = $7, lease_expires_at = NULL, completed_at = NULL, failed_at = $7
		WHERE tenant_id = $1 AND actor_key_id = $2 AND method = $3 AND path = $4 AND idempotency_key = $5
		  AND state = 'pending' AND owner_token_hash = $6
	`, key.TenantID, key.ActorID, key.Method, key.Path, key.IdempotencyKey, ownerTokenHash, now.UTC())
	if err != nil {
		return writeError("fail idempotency record", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r idempotency) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		return 0, app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `DELETE FROM idempotency_records WHERE expires_at <= $1`, now.UTC())
	if err != nil {
		return 0, writeError("delete expired idempotency records", err)
	}
	return result.RowsAffected(), nil
}

func (r idempotency) replaceExpired(ctx context.Context, reservation app.IdempotencyReservation) error {
	result, err := r.tx.Exec(ctx, `
		UPDATE idempotency_records
		SET request_hash = $6, state = 'pending', owner_token_hash = $7, status = 0, response = 'null'::jsonb,
		    created_at = $8, updated_at = $8, lease_expires_at = $9, completed_at = NULL, failed_at = NULL, expires_at = $10
		WHERE tenant_id = $1 AND actor_key_id = $2 AND method = $3 AND path = $4 AND idempotency_key = $5
	`, reservation.Key.TenantID, reservation.Key.ActorID, reservation.Key.Method, reservation.Key.Path, reservation.Key.IdempotencyKey,
		reservation.RequestHash, reservation.OwnerTokenHash, reservation.Now, reservation.LeaseExpiresAt, reservation.ExpiresAt)
	if err != nil {
		return writeError("replace expired idempotency record", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r idempotency) recoverPending(ctx context.Context, reservation app.IdempotencyReservation) error {
	result, err := r.tx.Exec(ctx, `
		UPDATE idempotency_records
		SET owner_token_hash = $6, updated_at = $7, lease_expires_at = $8
		WHERE tenant_id = $1 AND actor_key_id = $2 AND method = $3 AND path = $4 AND idempotency_key = $5
		  AND state = 'pending' AND request_hash = $9
		  AND (lease_expires_at IS NULL OR lease_expires_at <= $7)
	`, reservation.Key.TenantID, reservation.Key.ActorID, reservation.Key.Method, reservation.Key.Path, reservation.Key.IdempotencyKey,
		reservation.OwnerTokenHash, reservation.Now, reservation.LeaseExpiresAt, reservation.RequestHash)
	if err != nil {
		return writeError("recover pending idempotency record", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func scanIdempotencyRecord(row pgx.Row) (app.IdempotencyRecord, error) {
	var record app.IdempotencyRecord
	var response []byte
	var state string
	if err := row.Scan(&record.RequestHash, &state, &record.OwnerTokenHash, &record.Status, &response,
		&record.CreatedAt, &record.UpdatedAt, &record.LeaseExpiresAt, &record.CompletedAt, &record.FailedAt, &record.ExpiresAt); err != nil {
		return app.IdempotencyRecord{}, err
	}
	record.State = app.IdempotencyState(state)
	if string(response) != "null" && len(response) > 0 {
		if err := json.Unmarshal(response, &record.Response); err != nil {
			return app.IdempotencyRecord{}, fmt.Errorf("decode idempotency response: %w", err)
		}
	}
	return record, nil
}
