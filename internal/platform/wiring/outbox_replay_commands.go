package wiring

import (
	"context"
	"errors"
	"net/http"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

// BuildOutboxReplayCommand binds the operator mutation to the same unit of
// work as its HTTP idempotency record. No Ledger snapshot is loaded.
func BuildOutboxReplayCommand(factory app.UnitOfWorkFactory) (httpapi.OutboxReplayCommand, error) {
	if factory == nil {
		return nil, errors.New("outbox replay transactions are required")
	}
	service, err := operationsapp.NewOutboxReplayCommands(outboxReplayTransactions{factory: factory})
	if err != nil {
		return nil, err
	}
	return outboxReplayCommand{executor: app.IdempotencyUnitOfWork{Transactions: factory}, service: service}, nil
}

type outboxReplayCommand struct {
	executor app.IdempotencyUnitOfWork
	service  *operationsapp.OutboxReplayCommands
}

func (c outboxReplayCommand) ReplayIdempotent(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, jobID string) (int, any, error) {
	// Revoked instance authority must also block retrieval of an old replay.
	if err := application.AuthorizeInstanceScope(ctx, actor, app.ScopeInstanceAdmin); err != nil {
		return 0, nil, mapOutboxReplayError(err)
	}
	status, response, err := c.executor.WithBody(ctx, actor, method, path, key, body, func(ctx context.Context, _ app.Repositories) (int, any, error) {
		replay, err := c.service.ReplayTerminalJob(ctx, actor, jobID)
		if err != nil {
			return 0, nil, mapOutboxReplayError(err)
		}
		return http.StatusOK, app.OutboxReplay{JobID: replay.JobID, Status: replay.Status, ReplayedAt: replay.ReplayedAt}, nil
	})
	return status, response, mapOutboxReplayError(err)
}

type outboxReplayTransactions struct{ factory app.UnitOfWorkFactory }

func (t outboxReplayTransactions) ExecuteReplay(ctx context.Context, command func(context.Context, operationsapp.ReplayRepository) error) error {
	return app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repositories app.Repositories) error {
		if repositories.OutboxReplay == nil {
			return app.ErrValidation
		}
		return command(ctx, outboxReplayRepository{repository: repositories.OutboxReplay})
	})
}

type outboxReplayRepository struct{ repository app.OutboxReplayRepository }

func (r outboxReplayRepository) ReplayTerminalJob(ctx context.Context, id, actorID string) (operationsapp.OutboxReplay, error) {
	replay, err := r.repository.ReplayTerminalJob(ctx, id, actorID)
	if err != nil {
		return operationsapp.OutboxReplay{}, err
	}
	return operationsapp.OutboxReplay{JobID: replay.JobID, Status: replay.Status, ReplayedAt: replay.ReplayedAt}, nil
}

func mapOutboxReplayError(err error) error {
	switch {
	case errors.Is(err, operationsapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}

var _ httpapi.OutboxReplayCommand = outboxReplayCommand{}
