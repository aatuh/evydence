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

func BuildApprovalCommands(factory app.UnitOfWorkFactory) (*riskapp.ApprovalCommands, error) {
	if factory == nil {
		return nil, errors.New("approval transactions are required")
	}
	return riskapp.NewApprovalCommands(riskapp.ApprovalCommandConfig{Authorizer: riskapp.NewApprovalWriteAuthorizer(), Transactions: approvalTransactions{factory}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type approvalTransactions struct{ factory app.UnitOfWorkFactory }

func (t approvalTransactions) ExecuteApproval(ctx context.Context, fn func(context.Context, riskapp.ApprovalTransaction) error) error {
	return mapControlWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Governance.(riskapp.ApprovalReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, approvalTransaction{reader: r, writer: repos.Governance, audit: repos.Audit})
	}))
}

type approvalTransaction struct {
	reader riskapp.ApprovalReader
	writer app.GovernanceRepository
	audit  app.AuditRepository
}

func (t approvalTransaction) ReadApprovalSubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	v, err := t.reader.ReadApprovalSubject(ctx, tenant, kind, id)
	return v, mapControlWriteError(err)
}
func (t approvalTransaction) ApprovalEvidenceExists(ctx context.Context, tenant, id string) (bool, error) {
	v, err := t.reader.ApprovalEvidenceExists(ctx, tenant, id)
	return v, mapControlWriteError(err)
}
func (t approvalTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return riskapp.NewApprovalWriteAuthorizer().Authorize(ctx, a, r)
}
func (t approvalTransaction) InsertApprovalRecord(ctx context.Context, v riskdomain.ApprovalRecord) error {
	return mapControlWriteError(t.writer.InsertApprovalRecord(ctx, domain.ApprovalRecord{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, Decision: v.Decision, Reason: v.Reason, ApproverID: v.ApproverID, EvidenceID: v.EvidenceID, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (t approvalTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	return appendAuditEvent(ctx, t.audit, v)
}
