package app

import (
	"context"
	"errors"
	"time"
)

// withDurableIdempotency retains the compatibility Ledger command view while
// using the same repository-scoped transaction protocol as focused commands.
func (l *Ledger) withDurableIdempotency(ctx context.Context, reservation IdempotencyReservation, run IdempotencyCommand) (int, any, error) {
	l.transactionGate.Lock()
	defer l.transactionGate.Unlock()

	var commandLedger *Ledger
	executor := IdempotencyUnitOfWork{Transactions: l.unitOfWork, Now: l.now}
	execution, err := executor.withReservation(ctx, reservation, func(txCtx context.Context, _ Repositories) (IdempotentUnitOfWorkCommand, error) {
		var err error
		commandLedger, err = l.cloneForIdempotencyCommand(txCtx)
		if err != nil {
			return nil, err
		}
		return func(txCtx context.Context, _ Repositories) (int, any, error) {
			return run(txCtx, commandLedger)
		}, nil
	})
	if err != nil {
		return execution.status, execution.response, err
	}
	if execution.executed {
		if commandLedger == nil {
			return 0, nil, ErrValidation
		}
		commandLedger.publishCompletedIdempotency(reservation, execution.status, execution.replay, execution.completedAt)
		if err := l.publishCommittedIdempotencyCommand(context.WithoutCancel(ctx), commandLedger); err != nil {
			return 0, nil, err
		}
	}
	return execution.status, execution.response, nil
}

func (l *Ledger) cloneForIdempotencyCommand(ctx context.Context) (*Ledger, error) {
	l.mu.Lock()
	state, err := l.snapshotLocked()
	workerProjections := l.workerProjections
	config := Config{
		APIKeyPepper:                 string(l.pepper),
		Now:                          l.now,
		UnitOfWork:                   l.unitOfWork,
		ObjectStore:                  l.objects,
		BuildAttestationParser:       l.buildAttestationParser,
		DSSEPolicyVerifier:           l.dssePolicyVerifier,
		Retention:                    l.retention,
		Signer:                       l.signer,
		OIDC:                         l.oidc,
		ProviderAPI:                  l.providerAPI,
		Transparency:                 l.transparencyProofs,
		Outbox:                       l.outbox,
		ReadinessChecks:              append([]ReadinessCheck(nil), l.readinessChecks...),
		WorkerOwnedParserSideEffects: l.workerOwnedParsers,
	}
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}
	clone, err := NewLedgerWithContext(ctx, config)
	if err != nil {
		return nil, err
	}
	// The command clone intentionally does not own the aggregate Store, but it
	// must retain the read-only worker projection capability. Otherwise signed
	// bundles and customer packages created through idempotent HTTP routes can
	// observe the clone's stale snapshot instead of durable worker output.
	clone.workerProjections = workerProjections
	if err := clone.applyState(state); err != nil {
		return nil, err
	}
	return clone, nil
}

// publishCommittedIdempotencyCommand publishes a committed command to the
// local read model. When a durable store is configured it reloads the
// authoritative state rather than replacing the cache with the command's
// pre-transaction snapshot: outbox workers and other processes may have
// appended state (notably audit-chain entries) while this API process ran.
func (l *Ledger) publishCommittedIdempotencyCommand(ctx context.Context, commandLedger *Ledger) error {
	if l.store != nil {
		state, ok, err := l.store.LoadState(ctx)
		if err != nil {
			return err
		}
		if ok {
			l.mu.Lock()
			defer l.mu.Unlock()
			return l.applyState(state)
		}
	}
	commandLedger.mu.Lock()
	state, err := commandLedger.snapshotLocked()
	commandLedger.mu.Unlock()
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.applyState(state)
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

func (l *Ledger) withInMemoryIdempotency(ctx context.Context, reservation IdempotencyReservation, run IdempotencyCommand) (int, any, error) {
	result, err := l.reserveInMemoryIdempotency(ctx, reservation)
	if err != nil {
		return 0, nil, err
	}
	return l.finishIdempotencyReservation(ctx, reservation, result, func() (int, any, error) {
		return run(ctx, l)
	}, func(ctx context.Context, status int, response any) error {
		replayResponse, err := safeIdempotencyReplayResponse(response)
		if err != nil {
			return err
		}
		return l.completeInMemoryIdempotency(ctx, reservation, status, replayResponse)
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
			if errors.Is(err, ErrRetryableSigning) {
				l.releaseInMemoryIdempotency(reservation)
				return status, response, err
			}
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

func (l *Ledger) releaseInMemoryIdempotency(reservation IdempotencyReservation) {
	storeKey := NewIdempotencyRecordKey(reservation.Key.TenantID, reservation.Key.ActorID, reservation.Key.Method, reservation.Key.Path, reservation.Key.IdempotencyKey)
	l.mu.Lock()
	defer l.mu.Unlock()
	record, exists := l.idempotency[storeKey]
	if exists && record.State == IdempotencyPending && record.OwnerTokenHash == reservation.OwnerTokenHash {
		delete(l.idempotency, storeKey)
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
