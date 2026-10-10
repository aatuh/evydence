package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// This test-only locator contains capabilities, never aggregate data, secrets,
// locks or a state-store fallback. Native commands join the caller's actual
// transaction through app.ExecuteUnitOfWork.
type repositoryFixture struct {
	transactions app.UnitOfWorkFactory
	now          func() time.Time
}

func (f *repositoryFixture) ExecuteUnitOfWork(ctx context.Context, run app.UnitOfWorkCommand) error {
	if f == nil || ctx == nil {
		return app.ErrValidation
	}
	return app.ExecuteUnitOfWork(ctx, f.transactions, run)
}

func (f *repositoryFixture) commandContext(ctx context.Context) (context.Context, *repositoryFixture) {
	scoped := &repositoryFixture{transactions: f.transactions, now: f.now}
	return context.WithValue(ctx, catalogFixtureCommandContextKey{}, scoped), scoped
}

// Only explicit historical replay seeding uses these convenience methods. The
// HTTP executor below uses native transaction-scoped guards and replay directly.
func (f *repositoryFixture) WithIdempotency(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, run func(context.Context, *repositoryFixture) (int, any, error)) (int, any, error) {
	if f == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	x := app.IdempotencyUnitOfWork{Transactions: f.transactions, Now: f.now}
	return x.WithBody(ctx, actor, method, path, key, body, func(ctx context.Context, _ app.Repositories) (int, any, error) {
		ctx, scoped := f.commandContext(ctx)
		return run(ctx, scoped)
	})
}
func (f *repositoryFixture) WithIdempotencyRequestHash(ctx context.Context, actor domain.Actor, method, path, key, digest string, run func(context.Context, *repositoryFixture) (int, any, error)) (int, any, error) {
	if f == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	x := app.IdempotencyUnitOfWork{Transactions: f.transactions, Now: f.now}
	return x.WithBodyDigest(ctx, actor, method, path, key, digest, func(ctx context.Context, _ app.Repositories) (int, any, error) {
		ctx, scoped := f.commandContext(ctx)
		return run(ctx, scoped)
	})
}

func newLegacyLedgerFixture(cfg app.Config) *repositoryFixture {
	if cfg.Store != nil {
		panic("NewLedger does not load durable state; use NewLedgerWithContext")
	}
	ledger, err := newLegacyLedgerFixtureWithContext(context.Background(), cfg)
	if err != nil {
		panic("unexpected in-memory ledger initialization failure: " + err.Error())
	}
	return ledger
}

func newLegacyLedgerFixtureWithContext(ctx context.Context, cfg app.Config) (*repositoryFixture, error) {
	if ctx == nil {
		return nil, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &repositoryFixture{transactions: cfg.UnitOfWork, now: cfg.Now}, nil
}
