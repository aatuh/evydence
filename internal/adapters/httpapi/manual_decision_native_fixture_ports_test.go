package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type manualDecisionFixtureStorage interface {
	riskapp.VulnerabilityDecisionReader
	AppendVulnerabilityDecision(context.Context, riskdomain.VulnerabilityDecision, []riskapp.ActiveDecisionHead) error
}
type manualDecisionFixtureTransactions struct{ catalogFixtureCommands }
type manualDecisionFixtureTransaction struct {
	manualDecisionFixtureStorage
	audit app.AuditRepository
}

// The existing fixture UoW owns current authority, checked append/supersession
// and audits together, including when an outer replay transaction is active.
func (f manualDecisionFixtureTransactions) ExecuteVulnerabilityDecision(ctx context.Context, run func(context.Context, riskapp.VulnerabilityDecisionTransaction) error) error {
	if ctx == nil || run == nil {
		return riskapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		storage, ok := r.Decisions.(manualDecisionFixtureStorage)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, manualDecisionFixtureTransaction{storage, r.Audit})
	})
}
func (tx manualDecisionFixtureTransaction) Authorize(ctx context.Context, actor domain.Actor, request application.AuthorizationRequest) error {
	return riskapp.NewVulnerabilityDecisionWriteAuthorizer().Authorize(ctx, actor, request)
}
func (tx manualDecisionFixtureTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return (governanceFixtureTransaction{audit: tx.audit}).AppendAudit(ctx, event)
}
func (f riskCommandFixture) manualDecision() (*riskapp.VulnerabilityDecisionCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	return riskapp.NewVulnerabilityDecisionCommands(riskapp.VulnerabilityDecisionCommandConfig{Authorizer: riskapp.NewVulnerabilityDecisionWriteAuthorizer(), Transactions: manualDecisionFixtureTransactions(f), Clock: clock, IDs: ids})
}

func createFixtureManualDecision(ctx context.Context, ledger *app.Ledger, actor domain.Actor, finding string, input riskapp.CreateVulnerabilityDecisionInput) (domain.VulnerabilityDecision, error) {
	value, err := (riskCommandFixture{catalogFixtureCommands{ledger: ledger}}).CreateVulnerabilityDecision(ctx, actor, finding, input)
	return domain.VulnerabilityDecisionFromContextModel(value), err
}

var _ riskapp.VulnerabilityDecisionTransaction = manualDecisionFixtureTransaction{}
