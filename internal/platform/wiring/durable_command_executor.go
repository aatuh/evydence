package wiring

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func BuildDurableCommandExecutor(factory app.UnitOfWorkFactory) (httpapi.DurableCommandExecutor, error) {
	if factory == nil {
		return nil, errors.New("durable command transactions are required")
	}
	return durableCommandExecutor{factory}, nil
}

type durableCommandExecutor struct{ factory app.UnitOfWorkFactory }

func (e durableCommandExecutor) WithBodyReplayAuthorization(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, authorize func(context.Context) error, authorizeReplay func(context.Context, any) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if authorize == nil || authorizeReplay == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	x := app.IdempotencyUnitOfWork{Transactions: e.factory, Authorize: func(ctx context.Context, _ app.Repositories) error { return authorize(ctx) }, AuthorizeReplay: func(ctx context.Context, _ app.Repositories, response any) error {
		return authorizeReplay(ctx, response)
	}}
	return x.WithBody(ctx, actor, method, path, key, body, func(ctx context.Context, _ app.Repositories) (int, any, error) { return run(ctx) })
}

func (e durableCommandExecutor) WithBodyDigest(ctx context.Context, actor domain.Actor, method, path, key, digest string, authorize func(context.Context) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if authorize == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	executor := app.IdempotencyUnitOfWork{Transactions: e.factory, Authorize: func(ctx context.Context, _ app.Repositories) error { return authorize(ctx) }}
	return executor.WithBodyDigest(ctx, actor, method, path, key, digest, func(ctx context.Context, _ app.Repositories) (int, any, error) { return run(ctx) })
}

func (e durableCommandExecutor) WithBody(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, authorize func(context.Context) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if authorize == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	executor := app.IdempotencyUnitOfWork{Transactions: e.factory, Authorize: func(ctx context.Context, _ app.Repositories) error {
		return authorize(ctx)
	}}
	return executor.WithBody(ctx, actor, method, path, key, body, func(ctx context.Context, _ app.Repositories) (int, any, error) {
		return run(ctx)
	})
}
