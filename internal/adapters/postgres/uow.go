package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/logging"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
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
	repos := repositories.New(tx)
	reader, ok := repos.Risk.(riskapp.PolicyEvaluationReleaseReader)
	if !ok {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, app.ErrValidation
	}
	repos.PolicyEvaluationReader = policyEvaluationRepository{releaseReader: reader, tx: tx}
	repos.WorkerProjection = transactionWorkerProjectionStore{tx: tx}
	u := &unitOfWork{tx: tx, logger: logging.FromContext(ctx), correlation: logging.CorrelationFromContext(ctx), started: time.Now()}
	repos.Audit = observedAudit{inner: repos.Audit, owner: u}
	u.repositories = repos
	return u, nil
}

type unitOfWork struct {
	logger            *logging.Logger
	correlation       logging.Correlation
	started           time.Time
	auditObservations []logging.Fields
	tx                pgx.Tx
	repositories      app.Repositories

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
	logCtx := logging.WithCorrelation(logging.WithLogger(ctx, u.logger), u.correlation)
	if err := u.tx.Commit(ctx); err != nil {
		u.auditObservations = nil
		logging.Emit(logCtx, logging.Command, logging.Fields{Duration: time.Since(u.started), Result: logging.Uncertain, Retry: logging.Transient})
		return fmt.Errorf("commit unit of work: %w", err)
	}
	u.done = true
	logging.Emit(logCtx, logging.Command, logging.Fields{Duration: time.Since(u.started), Result: logging.Succeeded})
	for _, f := range u.auditObservations {
		logging.Emit(logCtx, logging.Audit, f)
	}
	u.auditObservations = nil
	return nil
}

func (u *unitOfWork) Rollback(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.done {
		return app.ErrConflict
	}
	u.auditObservations = nil
	if err := u.tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("rollback unit of work: %w", err)
	}
	u.done = true
	return nil
}

// Capture only safe receipt coordinates. Publishing is owned by Commit, after
// PostgreSQL confirms durability; rollback and uncertain commits discard them.
type observedAudit struct {
	inner app.AuditRepository
	owner *unitOfWork
}

func (r observedAudit) Append(ctx context.Context, e domain.AuditChainEntry) (domain.AuditChainEntry, error) {
	receipt, err := r.inner.Append(ctx, e)
	if err == nil && r.owner.logger != nil {
		r.owner.mu.Lock()
		r.owner.auditObservations = append(r.owner.auditObservations, logging.Fields{TenantID: receipt.TenantID, ResourceID: receipt.SubjectID, ReceiptID: receipt.ID, Result: logging.Succeeded})
		r.owner.mu.Unlock()
	}
	return receipt, err
}
