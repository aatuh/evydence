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

func BuildWaiverCommands(factory app.UnitOfWorkFactory) (*riskapp.WaiverCommands, error) {
	if factory == nil {
		return nil, errors.New("waiver transactions are required")
	}
	return riskapp.NewWaiverCommands(riskapp.WaiverCommandConfig{Authorizer: riskapp.NewWaiverWriteAuthorizer(), Transactions: waiverTransactions{factory}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type waiverTransactions struct{ factory app.UnitOfWorkFactory }

func (t waiverTransactions) ExecuteWaiver(ctx context.Context, fn func(context.Context, riskapp.WaiverTransaction) error) error {
	return mapControlWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Governance.(riskapp.WaiverCommandReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, waiverTransaction{reader: r, writer: repos.Governance, audit: repos.Audit})
	}))
}

type waiverTransaction struct {
	reader riskapp.WaiverCommandReader
	writer app.GovernanceRepository
	audit  app.AuditRepository
}

func (t waiverTransaction) ReadWaiverSubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	v, err := t.reader.ReadWaiverSubject(ctx, tenant, kind, id)
	return v, mapControlWriteError(err)
}
func (t waiverTransaction) ReadWaiverTransitionState(ctx context.Context, tenant, id string) (riskapp.WaiverTransitionState, error) {
	v, err := t.reader.ReadWaiverTransitionState(ctx, tenant, id)
	return v, mapControlWriteError(err)
}
func (t waiverTransaction) ReadWaiverForApproval(ctx context.Context, tenant, id string) (riskdomain.Waiver, error) {
	v, err := t.reader.ReadWaiverForApproval(ctx, tenant, id)
	return v, mapControlWriteError(err)
}
func (t waiverTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, r application.AuthorizationRequest) error {
	return riskapp.NewWaiverWriteAuthorizer().Authorize(ctx, actor, r)
}
func (t waiverTransaction) InsertWaiver(ctx context.Context, v riskdomain.Waiver) error {
	return mapControlWriteError(t.writer.InsertWaiver(ctx, domain.Waiver(v)))
}
func (t waiverTransaction) ApproveWaiver(ctx context.Context, v riskdomain.Waiver) error {
	return mapControlWriteError(t.writer.ApproveWaiver(ctx, domain.Waiver(v)))
}
func (t waiverTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	return appendAuditEvent(ctx, t.audit, v)
}
