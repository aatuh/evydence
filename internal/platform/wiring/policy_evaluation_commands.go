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

func BuildPolicyEvaluationCommands(factory app.UnitOfWorkFactory) (*riskapp.PolicyEvaluationCommands, error) {
	if factory == nil {
		return nil, errors.New("policy evaluation transactions are required")
	}
	return riskapp.NewPolicyEvaluationCommands(riskapp.PolicyEvaluationCommandConfig{Authorizer: riskapp.NewPolicyEvaluationAuthorizer(), Transactions: policyEvaluationTransactions{factory}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type policyEvaluationTransactions struct{ factory app.UnitOfWorkFactory }

func (t policyEvaluationTransactions) ExecutePolicyEvaluation(ctx context.Context, fn func(context.Context, riskapp.PolicyEvaluationTransaction) error) error {
	return mapControlWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader := repos.PolicyEvaluationReader
		if reader == nil || repos.Verification == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, policyEvaluationTransaction{reader, repos.Verification, repos.Audit})
	}))
}

type policyEvaluationTransaction struct {
	reader riskapp.PolicyEvaluationReader
	writer app.VerificationRepository
	audit  app.AuditRepository
}

func (t policyEvaluationTransaction) ReadPolicyEvaluationRelease(ctx context.Context, tenant, id string) (riskapp.GovernanceSubjectReference, error) {
	v, err := t.reader.ReadPolicyEvaluationRelease(ctx, tenant, id)
	return v, mapControlWriteError(err)
}
func (t policyEvaluationTransaction) ReadPolicyEvaluationSnapshot(ctx context.Context, tenant, id string, now time.Time) (riskapp.ReadinessSnapshot, error) {
	v, err := t.reader.ReadPolicyEvaluationSnapshot(ctx, tenant, id, now)
	return v, mapControlWriteError(err)
}
func (t policyEvaluationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return riskapp.NewPolicyEvaluationAuthorizer().Authorize(ctx, a, r)
}
func (t policyEvaluationTransaction) InsertPolicyEvaluation(ctx context.Context, v riskdomain.PolicyEvaluation) error {
	return mapControlWriteError(t.writer.InsertPolicyEvaluation(ctx, domain.PolicyEvaluationFromContext(v)))
}
func (t policyEvaluationTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	return appendAuditEvent(ctx, t.audit, v)
}
