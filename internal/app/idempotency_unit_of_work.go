package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

// IdempotentUnitOfWorkCommand receives only transaction-scoped repositories.
// It must not retain the context or repositories after returning.
type IdempotentUnitOfWorkCommand func(context.Context, Repositories) (int, any, error)

// IdempotencyUnitOfWork executes a command and its safe replay record in one
// transaction without constructing or loading a Ledger aggregate. Failed
// execution returns no status or response, including partial callback output.
type IdempotencyUnitOfWork struct {
	Transactions UnitOfWorkFactory
	Now          func() time.Time
	// Authorize is a request-scoped, read-only check of current access, run in
	// the active transaction before reservation, including replay and failure.
	// Omit only when the caller already enforces its current replay policy.
	Authorize func(context.Context, Repositories) error
}

type idempotencyExecution struct {
	status      int
	response    any
	replay      any
	executed    bool
	completedAt time.Time
}

func (executor IdempotencyUnitOfWork) WithBody(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, run IdempotentUnitOfWorkCommand) (int, any, error) {
	requestHash := hashBytes(append([]byte(method+"\n"+path+"\n"), body...))
	return executor.withRequestHash(ctx, actor, method, path, key, requestHash, run)
}

// WithBodyDigest accepts a full-body digest for streaming routes. Method and
// path remain part of the persisted request fingerprint.
func (executor IdempotencyUnitOfWork) WithBodyDigest(ctx context.Context, actor domain.Actor, method, path, key, bodyDigest string, run IdempotentUnitOfWorkCommand) (int, any, error) {
	if !validDigest(bodyDigest) {
		return 0, nil, ErrValidation
	}
	requestHash := hashBytes([]byte(method + "\n" + path + "\n" + bodyDigest))
	return executor.withRequestHash(ctx, actor, method, path, key, requestHash, run)
}

func (executor IdempotencyUnitOfWork) withRequestHash(ctx context.Context, actor domain.Actor, method, path, key, requestHash string, run IdempotentUnitOfWorkCommand) (int, any, error) {
	if ctx == nil || executor.Transactions == nil || run == nil || strings.TrimSpace(key) == "" || !validDigest(requestHash) {
		return 0, nil, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	reservation, err := newIdempotencyReservation(IdempotencyRecordKey{
		TenantID: actor.TenantID, ActorID: idempotencyActorID(actor), Method: method,
		Path: path, IdempotencyKey: strings.TrimSpace(key),
	}, requestHash, executor.now())
	if err != nil {
		return 0, nil, err
	}
	result, err := executor.withReservation(ctx, reservation, func(context.Context, Repositories) (IdempotentUnitOfWorkCommand, error) {
		return run, nil
	})
	return result.status, result.response, err
}

func (executor IdempotencyUnitOfWork) withReservation(ctx context.Context, reservation IdempotencyReservation, prepare func(context.Context, Repositories) (IdempotentUnitOfWorkCommand, error)) (idempotencyExecution, error) {
	if ctx == nil || executor.Transactions == nil || prepare == nil {
		return idempotencyExecution{}, ErrValidation
	}
	var result IdempotencyReservationResult
	var execution idempotencyExecution
	var commandErr error
	err := ExecuteUnitOfWork(ctx, executor.Transactions, func(txCtx context.Context, repositories Repositories) error {
		if repositories.Idempotency == nil {
			return ErrValidation
		}
		if executor.Authorize != nil {
			if err := executor.Authorize(withActiveRepositories(txCtx, repositories), repositories); err != nil {
				return err
			}
		}
		var err error
		result, err = repositories.Idempotency.Reserve(txCtx, reservation)
		if err != nil {
			return err
		}
		switch result.Outcome {
		case IdempotencyReservationReplay, IdempotencyReservationPending, IdempotencyReservationFailure:
			return nil
		case IdempotencyReservationAcquired, IdempotencyReservationRecovered:
			run, err := prepare(txCtx, repositories)
			if err != nil {
				return err
			}
			if run == nil {
				return ErrValidation
			}
			execution.executed = true
			execution.status, execution.response, commandErr = run(withActiveRepositories(txCtx, repositories), repositories)
			if commandErr != nil {
				return commandErr
			}
			replayResponse, err := safeIdempotencyReplayResponse(execution.response)
			if err != nil {
				return err
			}
			execution.replay = replayResponse
			execution.completedAt = executor.now().UTC()
			return repositories.Idempotency.Complete(txCtx, reservation.Key, reservation.OwnerTokenHash, execution.status, replayResponse, execution.completedAt)
		default:
			return ErrValidation
		}
	})
	if execution.executed && commandErr != nil && !errors.Is(commandErr, ErrRetryableSigning) {
		// The command transaction rolled back. A separate safe failure record
		// cannot make any partial command mutation durable.
		_ = executor.persistFailure(context.WithoutCancel(ctx), reservation)
		return idempotencyExecution{}, commandErr
	}
	if err != nil {
		return idempotencyExecution{}, err
	}
	switch result.Outcome {
	case IdempotencyReservationReplay:
		record, err := replayableIdempotencyRecord(result.Record)
		if err != nil {
			return idempotencyExecution{}, err
		}
		return idempotencyExecution{status: record.Status, response: record.Response}, nil
	case IdempotencyReservationPending:
		return idempotencyExecution{}, ErrIdempotencyInProgress
	case IdempotencyReservationFailure:
		return idempotencyExecution{}, ErrIdempotencyFailed
	case IdempotencyReservationAcquired, IdempotencyReservationRecovered:
		return execution, nil
	default:
		return idempotencyExecution{}, ErrValidation
	}
}

func (executor IdempotencyUnitOfWork) persistFailure(ctx context.Context, reservation IdempotencyReservation) error {
	return ExecuteUnitOfWork(ctx, executor.Transactions, func(txCtx context.Context, repositories Repositories) error {
		if repositories.Idempotency == nil {
			return ErrValidation
		}
		result, err := repositories.Idempotency.Reserve(txCtx, reservation)
		if err != nil {
			return err
		}
		switch result.Outcome {
		case IdempotencyReservationAcquired, IdempotencyReservationRecovered:
			return repositories.Idempotency.Fail(txCtx, reservation.Key, reservation.OwnerTokenHash, executor.now().UTC())
		case IdempotencyReservationReplay, IdempotencyReservationPending, IdempotencyReservationFailure:
			return nil
		default:
			return ErrValidation
		}
	})
}

func (executor IdempotencyUnitOfWork) now() time.Time {
	if executor.Now != nil {
		return executor.Now()
	}
	return time.Now()
}
