package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func BuildExceptionCommands(factory app.UnitOfWorkFactory) (*riskapp.ExceptionCommands, error) {
	if factory == nil {
		return nil, errors.New("exception transactions are required")
	}
	return riskapp.NewExceptionCommands(riskapp.ExceptionCommandConfig{Authorizer: riskapp.NewExceptionWriteAuthorizer(), Transactions: exceptionTransactions{factory}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type exceptionTransactions struct{ factory app.UnitOfWorkFactory }

func (t exceptionTransactions) ExecuteException(ctx context.Context, fn func(context.Context, riskapp.ExceptionTransaction) error) error {
	return mapControlWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Decisions.(riskapp.ExceptionCommandReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, exceptionTransaction{reader: r, writer: repos.Decisions, audit: repos.Audit})
	}))
}

type exceptionTransaction struct {
	reader riskapp.ExceptionCommandReader
	writer app.DecisionRepository
	audit  app.AuditRepository
}

func (t exceptionTransaction) ReadExceptionSubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	v, err := t.reader.ReadExceptionSubject(ctx, tenant, kind, id)
	return v, mapControlWriteError(err)
}
func (t exceptionTransaction) ReadExceptionTransitionState(ctx context.Context, tenant, id string) (riskapp.ExceptionTransitionState, error) {
	v, err := t.reader.ReadExceptionTransitionState(ctx, tenant, id)
	return v, mapControlWriteError(err)
}
func (t exceptionTransaction) ReadExceptionForApproval(ctx context.Context, tenant, id string) (riskdomain.Exception, error) {
	v, err := t.reader.ReadExceptionForApproval(ctx, tenant, id)
	return v, mapControlWriteError(err)
}
func (t exceptionTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, r application.AuthorizationRequest) error {
	return riskapp.NewExceptionWriteAuthorizer().Authorize(ctx, actor, r)
}
func (t exceptionTransaction) InsertException(ctx context.Context, v riskdomain.Exception) error {
	return mapControlWriteError(t.writer.InsertException(ctx, domain.Exception(v)))
}
func (t exceptionTransaction) ApproveException(ctx context.Context, v riskdomain.Exception) error {
	return mapControlWriteError(t.writer.ApproveException(ctx, domain.Exception(v)))
}
func (t exceptionTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	return appendAuditEvent(ctx, t.audit, v)
}
