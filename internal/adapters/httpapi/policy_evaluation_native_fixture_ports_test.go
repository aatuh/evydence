package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Test-only composition of the same focused command as production. One current
// UoW owns release authority, bounded facts, evaluation insertion and audit.
type policyEvaluationFixtureTransactions struct{ catalogFixtureCommands }
type policyEvaluationFixtureTransaction struct {
	riskapp.PolicyEvaluationReader
	writer app.VerificationRepository
	audit  app.AuditRepository
}

func (f policyEvaluationFixtureTransactions) ExecutePolicyEvaluation(ctx context.Context, run func(context.Context, riskapp.PolicyEvaluationTransaction) error) error {
	if ctx == nil || run == nil {
		return riskapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if r.PolicyEvaluationReader == nil || r.Verification == nil || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, policyEvaluationFixtureTransaction{PolicyEvaluationReader: r.PolicyEvaluationReader, writer: r.Verification, audit: r.Audit})
	})
}
func (tx policyEvaluationFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, request application.AuthorizationRequest) error {
	return riskapp.NewPolicyEvaluationAuthorizer().Authorize(ctx, a, request)
}
func (tx policyEvaluationFixtureTransaction) InsertPolicyEvaluation(ctx context.Context, value riskdomain.PolicyEvaluation) error {
	return tx.writer.InsertPolicyEvaluation(ctx, domain.PolicyEvaluationFromContext(value))
}
func (tx policyEvaluationFixtureTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return (governanceFixtureTransaction{audit: tx.audit}).AppendAudit(ctx, event)
}
func (f riskCommandFixture) policyEvaluation() (*riskapp.PolicyEvaluationCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	return riskapp.NewPolicyEvaluationCommands(riskapp.PolicyEvaluationCommandConfig{Authorizer: riskapp.NewPolicyEvaluationAuthorizer(), Transactions: policyEvaluationFixtureTransactions(f), Clock: clock, IDs: ids})
}
func policyEvaluationFixtureError(err error) error {
	switch {
	case errors.Is(err, riskapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, riskapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, riskapp.ErrConflict):
		return app.ErrConflict
	default:
		return err
	}
}

var _ riskapp.PolicyEvaluationTransaction = policyEvaluationFixtureTransaction{}
