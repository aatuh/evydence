package app

import (
	"context"
	"strings"
	"time"
)

// IdempotencyState is the durable lifecycle for one tenant-and-actor scoped
// request key. Pending records have an owner lease; only a matching owner can
// transition them to a terminal state.
type IdempotencyState string

const (
	IdempotencyPending   IdempotencyState = "pending"
	IdempotencyCompleted IdempotencyState = "completed"
	IdempotencyFailed    IdempotencyState = "failed"

	defaultIdempotencyLease     = 2 * time.Minute
	defaultIdempotencyRetention = 24 * time.Hour
)

type IdempotencyRecord struct {
	State          IdempotencyState `json:"state"`
	RequestHash    string           `json:"request_hash"`
	OwnerTokenHash string           `json:"owner_token_hash,omitempty"`
	Status         int              `json:"status"`
	Response       any              `json:"response,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	LeaseExpiresAt *time.Time       `json:"lease_expires_at,omitempty"`
	CompletedAt    *time.Time       `json:"completed_at,omitempty"`
	FailedAt       *time.Time       `json:"failed_at,omitempty"`
	ExpiresAt      time.Time        `json:"expires_at"`
}

type IdempotencyRecordKey struct {
	TenantID       string
	ActorID        string
	Method         string
	Path           string
	IdempotencyKey string
}

// IdempotencyReservation contains only digests and the hash of a random
// server-generated owner token. Raw request bytes and raw owner tokens are
// deliberately never persisted or logged.
type IdempotencyReservation struct {
	Key            IdempotencyRecordKey
	RequestHash    string
	OwnerTokenHash string
	Now            time.Time
	LeaseExpiresAt time.Time
	ExpiresAt      time.Time
}

type IdempotencyReservationOutcome string

const (
	IdempotencyReservationAcquired  IdempotencyReservationOutcome = "acquired"
	IdempotencyReservationRecovered IdempotencyReservationOutcome = "recovered"
	IdempotencyReservationReplay    IdempotencyReservationOutcome = "replay"
	IdempotencyReservationPending   IdempotencyReservationOutcome = "pending"
	IdempotencyReservationFailure   IdempotencyReservationOutcome = "failed"
)

type IdempotencyReservationResult struct {
	Outcome IdempotencyReservationOutcome
	Record  IdempotencyRecord
}

func newIdempotencyReservation(key IdempotencyRecordKey, requestHash string, now time.Time) (IdempotencyReservation, error) {
	now = now.UTC()
	if err := validateIdempotencyKey(key); err != nil || strings.TrimSpace(requestHash) == "" || now.IsZero() {
		return IdempotencyReservation{}, ErrValidation
	}
	ownerToken := randomToken(32)
	return IdempotencyReservation{
		Key:            key,
		RequestHash:    requestHash,
		OwnerTokenHash: hashBytes([]byte(ownerToken)),
		Now:            now,
		LeaseExpiresAt: now.Add(defaultIdempotencyLease),
		ExpiresAt:      now.Add(defaultIdempotencyRetention),
	}, nil
}

func validateIdempotencyKey(key IdempotencyRecordKey) error {
	if strings.TrimSpace(key.TenantID) == "" || strings.TrimSpace(key.ActorID) == "" || strings.TrimSpace(key.Method) == "" || strings.TrimSpace(key.Path) == "" || strings.TrimSpace(key.IdempotencyKey) == "" {
		return ErrValidation
	}
	return nil
}

// ValidateIdempotencyKey validates the tenant-and-actor scoped key before a
// persistence adapter uses it in a state transition.
func ValidateIdempotencyKey(key IdempotencyRecordKey) error {
	return validateIdempotencyKey(key)
}

func validateIdempotencyReservation(reservation IdempotencyReservation) error {
	if err := validateIdempotencyKey(reservation.Key); err != nil || strings.TrimSpace(reservation.RequestHash) == "" || strings.TrimSpace(reservation.OwnerTokenHash) == "" || reservation.Now.IsZero() || reservation.LeaseExpiresAt.IsZero() || reservation.ExpiresAt.IsZero() || !reservation.LeaseExpiresAt.After(reservation.Now) || !reservation.ExpiresAt.After(reservation.Now) {
		return ErrValidation
	}
	return nil
}

// ValidateIdempotencyReservation validates a reservation before acquisition.
func ValidateIdempotencyReservation(reservation IdempotencyReservation) error {
	return validateIdempotencyReservation(reservation)
}

func normalizeLegacyIdempotencyRecord(record IdempotencyRecord) (IdempotencyRecord, error) {
	if strings.TrimSpace(record.RequestHash) == "" || record.CreatedAt.IsZero() || record.Status < 100 || record.Status > 599 {
		return IdempotencyRecord{}, ErrValidation
	}
	if record.State == "" {
		record.State = IdempotencyCompleted
	}
	if record.State != IdempotencyCompleted {
		return IdempotencyRecord{}, ErrValidation
	}
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = record.CreatedAt
	}
	if record.CompletedAt == nil {
		completedAt := record.CreatedAt
		record.CompletedAt = &completedAt
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = record.CreatedAt.Add(defaultIdempotencyRetention)
	}
	record.OwnerTokenHash = ""
	record.LeaseExpiresAt = nil
	record.FailedAt = nil
	return record, nil
}

// NormalizeLegacyIdempotencyRecord upgrades a pre-state-machine completed
// record in memory without changing its response or request digest.
func NormalizeLegacyIdempotencyRecord(record IdempotencyRecord) (IdempotencyRecord, error) {
	return normalizeLegacyIdempotencyRecord(record)
}

func replayableIdempotencyRecord(record IdempotencyRecord) (IdempotencyRecord, error) {
	if record.State == "" {
		return normalizeLegacyIdempotencyRecord(record)
	}
	if record.State != IdempotencyCompleted || strings.TrimSpace(record.RequestHash) == "" || record.Status < 100 || record.Status > 599 || record.ExpiresAt.IsZero() {
		return IdempotencyRecord{}, ErrValidation
	}
	return record, nil
}

func (l *Ledger) withDurableIdempotency(ctx context.Context, reservation IdempotencyReservation, run func() (int, any, error)) (int, any, error) {
	var result IdempotencyReservationResult
	if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repositories Repositories) error {
		var err error
		result, err = repositories.Idempotency.Reserve(ctx, reservation)
		return err
	}); err != nil {
		return 0, nil, err
	}
	return l.finishIdempotencyReservation(ctx, reservation, result, run, func(ctx context.Context, status int, response any) error {
		completedAt := l.now().UTC()
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repositories Repositories) error {
			return repositories.Idempotency.Complete(ctx, reservation.Key, reservation.OwnerTokenHash, status, response, completedAt)
		}); err != nil {
			return err
		}
		l.publishCompletedIdempotency(reservation, status, response, completedAt)
		return nil
	}, func(ctx context.Context) error {
		return l.ExecuteUnitOfWork(context.WithoutCancel(ctx), func(ctx context.Context, repositories Repositories) error {
			return repositories.Idempotency.Fail(ctx, reservation.Key, reservation.OwnerTokenHash, l.now())
		})
	})
}

func (l *Ledger) publishCompletedIdempotency(reservation IdempotencyReservation, status int, response any, completedAt time.Time) {
	record := IdempotencyRecord{
		State:       IdempotencyCompleted,
		RequestHash: reservation.RequestHash,
		Status:      status,
		Response:    response,
		CreatedAt:   reservation.Now,
		UpdatedAt:   completedAt,
		CompletedAt: &completedAt,
		ExpiresAt:   reservation.ExpiresAt,
	}
	storeKey := NewIdempotencyRecordKey(reservation.Key.TenantID, reservation.Key.ActorID, reservation.Key.Method, reservation.Key.Path, reservation.Key.IdempotencyKey)
	l.mu.Lock()
	l.idempotency[storeKey] = record
	l.mu.Unlock()
}

func (l *Ledger) withInMemoryIdempotency(ctx context.Context, reservation IdempotencyReservation, run func() (int, any, error)) (int, any, error) {
	result, err := l.reserveInMemoryIdempotency(ctx, reservation)
	if err != nil {
		return 0, nil, err
	}
	return l.finishIdempotencyReservation(ctx, reservation, result, run, func(ctx context.Context, status int, response any) error {
		return l.completeInMemoryIdempotency(ctx, reservation, status, response)
	}, func(ctx context.Context) error {
		return l.failInMemoryIdempotency(context.WithoutCancel(ctx), reservation)
	})
}

func (l *Ledger) finishIdempotencyReservation(ctx context.Context, reservation IdempotencyReservation, result IdempotencyReservationResult, run func() (int, any, error), complete func(context.Context, int, any) error, fail func(context.Context) error) (int, any, error) {
	switch result.Outcome {
	case IdempotencyReservationReplay:
		record, err := replayableIdempotencyRecord(result.Record)
		if err != nil {
			return 0, nil, err
		}
		return record.Status, record.Response, nil
	case IdempotencyReservationPending:
		return 0, nil, ErrIdempotencyInProgress
	case IdempotencyReservationFailure:
		return 0, nil, ErrIdempotencyFailed
	case IdempotencyReservationAcquired, IdempotencyReservationRecovered:
		status, response, err := run()
		if err != nil {
			// Failure state records no raw error or partial response. A later ticket
			// defines which documented client failures may be replayed safely.
			_ = fail(ctx)
			return status, response, err
		}
		if err := complete(ctx, status, response); err != nil {
			return 0, nil, err
		}
		return status, response, nil
	default:
		return 0, nil, ErrValidation
	}
}

func (l *Ledger) reserveInMemoryIdempotency(ctx context.Context, reservation IdempotencyReservation) (IdempotencyReservationResult, error) {
	if err := ctx.Err(); err != nil {
		return IdempotencyReservationResult{}, err
	}
	if err := validateIdempotencyReservation(reservation); err != nil {
		return IdempotencyReservationResult{}, err
	}
	storeKey := NewIdempotencyRecordKey(reservation.Key.TenantID, reservation.Key.ActorID, reservation.Key.Method, reservation.Key.Path, reservation.Key.IdempotencyKey)
	l.mu.Lock()
	defer l.mu.Unlock()
	record, exists := l.idempotency[storeKey]
	if exists {
		if record.State == "" {
			var err error
			record, err = normalizeLegacyIdempotencyRecord(record)
			if err != nil {
				return IdempotencyReservationResult{}, err
			}
		}
		if !record.ExpiresAt.After(reservation.Now) {
		} else if record.RequestHash != reservation.RequestHash {
			return IdempotencyReservationResult{}, ErrIdempotencyConflict
		} else {
			switch record.State {
			case IdempotencyCompleted:
				return IdempotencyReservationResult{Outcome: IdempotencyReservationReplay, Record: record}, nil
			case IdempotencyFailed:
				return IdempotencyReservationResult{Outcome: IdempotencyReservationFailure, Record: record}, nil
			case IdempotencyPending:
				if record.LeaseExpiresAt != nil && record.LeaseExpiresAt.After(reservation.Now) {
					return IdempotencyReservationResult{Outcome: IdempotencyReservationPending, Record: record}, nil
				}
				recovered := recoveredPendingIdempotencyRecord(record, reservation)
				l.idempotency[storeKey] = recovered
				if err := l.persistCriticalStateLocked(ctx); err != nil {
					l.idempotency[storeKey] = record
					return IdempotencyReservationResult{}, err
				}
				return IdempotencyReservationResult{Outcome: IdempotencyReservationRecovered, Record: recovered}, nil
			default:
				return IdempotencyReservationResult{}, ErrValidation
			}
		}
	}
	pending := pendingIdempotencyRecord(reservation)
	l.idempotency[storeKey] = pending
	if err := l.persistCriticalStateLocked(ctx); err != nil {
		delete(l.idempotency, storeKey)
		return IdempotencyReservationResult{}, err
	}
	return IdempotencyReservationResult{Outcome: IdempotencyReservationAcquired, Record: pending}, nil
}

func (l *Ledger) completeInMemoryIdempotency(ctx context.Context, reservation IdempotencyReservation, status int, response any) error {
	if status < 100 || status > 599 {
		return ErrValidation
	}
	storeKey := NewIdempotencyRecordKey(reservation.Key.TenantID, reservation.Key.ActorID, reservation.Key.Method, reservation.Key.Path, reservation.Key.IdempotencyKey)
	l.mu.Lock()
	defer l.mu.Unlock()
	record, ok := l.idempotency[storeKey]
	if !ok || record.State != IdempotencyPending || record.OwnerTokenHash != reservation.OwnerTokenHash {
		return ErrConflict
	}
	previous := record
	now := l.now().UTC()
	record.State = IdempotencyCompleted
	record.OwnerTokenHash = ""
	record.Status = status
	record.Response = response
	record.UpdatedAt = now
	record.LeaseExpiresAt = nil
	record.CompletedAt = &now
	record.FailedAt = nil
	l.idempotency[storeKey] = record
	if err := l.persistCriticalStateLocked(ctx); err != nil {
		l.idempotency[storeKey] = previous
		return err
	}
	return nil
}

func (l *Ledger) failInMemoryIdempotency(ctx context.Context, reservation IdempotencyReservation) error {
	storeKey := NewIdempotencyRecordKey(reservation.Key.TenantID, reservation.Key.ActorID, reservation.Key.Method, reservation.Key.Path, reservation.Key.IdempotencyKey)
	l.mu.Lock()
	defer l.mu.Unlock()
	record, ok := l.idempotency[storeKey]
	if !ok || record.State != IdempotencyPending || record.OwnerTokenHash != reservation.OwnerTokenHash {
		return ErrConflict
	}
	previous := record
	now := l.now().UTC()
	record.State = IdempotencyFailed
	record.OwnerTokenHash = ""
	record.Status = 0
	record.Response = nil
	record.UpdatedAt = now
	record.LeaseExpiresAt = nil
	record.FailedAt = &now
	l.idempotency[storeKey] = record
	if err := l.persistCriticalStateLocked(ctx); err != nil {
		l.idempotency[storeKey] = previous
		return err
	}
	return nil
}

func pendingIdempotencyRecord(reservation IdempotencyReservation) IdempotencyRecord {
	leaseExpiresAt := reservation.LeaseExpiresAt
	return IdempotencyRecord{
		State:          IdempotencyPending,
		RequestHash:    reservation.RequestHash,
		OwnerTokenHash: reservation.OwnerTokenHash,
		CreatedAt:      reservation.Now,
		UpdatedAt:      reservation.Now,
		LeaseExpiresAt: &leaseExpiresAt,
		ExpiresAt:      reservation.ExpiresAt,
	}
}

// PendingIdempotencyRecord returns the first durable state for a reservation.
func PendingIdempotencyRecord(reservation IdempotencyReservation) IdempotencyRecord {
	return pendingIdempotencyRecord(reservation)
}

func recoveredPendingIdempotencyRecord(previous IdempotencyRecord, reservation IdempotencyReservation) IdempotencyRecord {
	recovered := pendingIdempotencyRecord(reservation)
	recovered.CreatedAt = previous.CreatedAt
	recovered.ExpiresAt = previous.ExpiresAt
	return recovered
}

// RecoveredPendingIdempotencyRecord preserves original retention while giving
// an expired lease a new owner.
func RecoveredPendingIdempotencyRecord(previous IdempotencyRecord, reservation IdempotencyReservation) IdempotencyRecord {
	return recoveredPendingIdempotencyRecord(previous, reservation)
}
