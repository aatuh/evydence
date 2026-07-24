package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
)

// BeginUnitOfWork begins one PostgreSQL transaction for a command. Focused
// repositories share that transaction so domain, audit, idempotency, and
// outbox effects become visible only after Commit succeeds.
func (s *Store) BeginUnitOfWork(ctx context.Context) (app.UnitOfWork, error) {
	if s == nil || s.pool == nil {
		return nil, app.ErrValidation
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin unit of work: %w", err)
	}
	return &unitOfWork{tx: tx, repositories: repositories.New(tx)}, nil
}

type unitOfWork struct {
	tx           pgx.Tx
	repositories app.Repositories

	mu   sync.Mutex
	done bool
}

func (u *unitOfWork) Repositories() app.Repositories {
	return u.repositories
}

func (u *unitOfWork) Commit(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.done {
		return app.ErrConflict
	}
	if err := u.tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit unit of work: %w", err)
	}
	u.done = true
	return nil
}

func (u *unitOfWork) Rollback(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.done {
		return app.ErrConflict
	}
	if err := u.tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("rollback unit of work: %w", err)
	}
	u.done = true
	return nil
}
