package app

import (
	"context"
	"fmt"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

// UnitOfWorkCommand receives repositories bound to one command transaction.
// It must not retain them after returning.
type UnitOfWorkCommand func(context.Context, Repositories) error

type activeUnitOfWorkContextKey struct{}

type activeUnitOfWork struct {
	repositories Repositories
}

func activeRepositories(ctx context.Context) (Repositories, bool) {
	active, ok := ctx.Value(activeUnitOfWorkContextKey{}).(activeUnitOfWork)
	return active.repositories, ok
}

func withActiveRepositories(ctx context.Context, repositories Repositories) context.Context {
	return context.WithValue(ctx, activeUnitOfWorkContextKey{}, activeUnitOfWork{repositories: repositories})
}

// newUnitOfWorkAuditEntry creates an unsequenced audit entry for a command
// transaction. The transaction-scoped audit repository assigns the durable
// sequence and predecessor hash before the command is committed.
func newUnitOfWorkAuditEntry(now time.Time, tenantID, entryType, subjectType, subjectID, actorType, actorID, payloadHash, signatureRef string) domain.AuditChainEntry {
	return domain.AuditChainEntry{
		ID:            newID("ace"),
		TenantID:      tenantID,
		EntryType:     entryType,
		SubjectType:   subjectType,
		SubjectID:     subjectID,
		ActorType:     actorType,
		ActorID:       actorID,
		OccurredAt:    now,
		PayloadHash:   payloadHash,
		SignatureRef:  signatureRef,
		SchemaVersion: domain.AuditChainEntrySchemaVersion,
	}
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
	if repositories, ok := activeRepositories(ctx); ok {
		return command(ctx, repositories)
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
