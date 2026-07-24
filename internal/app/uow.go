package app

import (
	"context"
	"fmt"
)

// UnitOfWorkCommand receives repositories bound to one command transaction.
// It must not retain them after returning.
type UnitOfWorkCommand func(context.Context, Repositories) error

// ExecuteUnitOfWork runs a transaction-backed application command using this
// ledger's configured persistence factory.
func (l *Ledger) ExecuteUnitOfWork(ctx context.Context, command UnitOfWorkCommand) error {
	if l == nil || l.unitOfWork == nil {
		return ErrValidation
	}
	return ExecuteUnitOfWork(ctx, l.unitOfWork, command)
}

// ExecuteUnitOfWork runs a command with focused transaction-scoped
// repositories. A command failure, cancellation, or commit failure rolls back
// all uncommitted effects before the error is returned.
func ExecuteUnitOfWork(ctx context.Context, factory UnitOfWorkFactory, command UnitOfWorkCommand) (err error) {
	if factory == nil || command == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	uow, err := factory.BeginUnitOfWork(ctx)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := uow.Rollback(context.WithoutCancel(ctx)); rollbackErr != nil && err == nil {
			err = fmt.Errorf("rollback unit of work: %w", rollbackErr)
		}
	}()
	if err := command(ctx, uow.Repositories()); err != nil {
		return err
	}
	if err := uow.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}
