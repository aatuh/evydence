package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type riskWorkflowNativeFixtureTransactions struct{ catalogFixtureCommands }
type riskWorkflowNativeFixtureTransaction struct {
	riskapp.CustomPolicyReader
	riskapp.VulnerabilityWorkflowReader
	writer app.RiskRepository
	audit  app.AuditRepository
}

func (f riskWorkflowNativeFixtureTransactions) execute(ctx context.Context, run func(context.Context, riskWorkflowNativeFixtureTransaction) error) error {
	if ctx == nil || run == nil {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		policy, ok := r.Risk.(riskapp.CustomPolicyReader)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		workflow, ok := r.Risk.(riskapp.VulnerabilityWorkflowReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, riskWorkflowNativeFixtureTransaction{CustomPolicyReader: policy, VulnerabilityWorkflowReader: workflow, writer: r.Risk, audit: r.Audit})
	})
}
func (f riskWorkflowNativeFixtureTransactions) ExecuteCustomPolicy(ctx context.Context, run func(context.Context, riskapp.CustomPolicyTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx riskWorkflowNativeFixtureTransaction) error { return run(ctx, tx) })
}
func (f riskWorkflowNativeFixtureTransactions) ExecuteVulnerabilityWorkflow(ctx context.Context, run func(context.Context, riskapp.VulnerabilityWorkflowTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx riskWorkflowNativeFixtureTransaction) error { return run(ctx, tx) })
}
func (tx riskWorkflowNativeFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return (riskWorkflowFixtureGuard{}).Authorize(ctx, a, r)
}
func (tx riskWorkflowNativeFixtureTransaction) InsertCustomPolicy(ctx context.Context, p riskdomain.CustomPolicy) error {
	return tx.writer.InsertCustomPolicy(ctx, domain.CustomPolicyFromContext(p))
}
func (tx riskWorkflowNativeFixtureTransaction) InsertCustomPolicyEvaluation(ctx context.Context, p riskdomain.CustomPolicyEvaluation) error {
	return tx.writer.InsertCustomPolicyEvaluation(ctx, domain.CustomPolicyEvaluationFromContext(p))
}
func (tx riskWorkflowNativeFixtureTransaction) InsertVulnerabilityWorkflow(ctx context.Context, p riskdomain.VulnerabilityWorkflowRecord) error {
	return tx.writer.InsertVulnerabilityWorkflow(ctx, domain.VulnerabilityWorkflowRecord(p))
}
func (tx riskWorkflowNativeFixtureTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return (governanceFixtureTransaction{audit: tx.audit}).AppendAudit(ctx, event)
}

type riskWorkflowNativeFixtureHasher struct{}

func (riskWorkflowNativeFixtureHasher) HashCustomPolicy(p riskdomain.CustomPolicy, release string, checks []riskdomain.PolicyCheck) (string, error) {
	return application.NormalizedJSONHash(map[string]any{"policy": domain.CustomPolicyFromContext(p), "release_id": release, "checks": domain.CustomPolicyChecksFromContext(checks)})
}
func (f riskWorkflowFixtureCommands) clockIDs() (application.Clock, application.IDGenerator) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	if f.ids != nil {
		ids = f.ids
	}
	return clock, ids
}
func (f riskWorkflowFixtureCommands) nativePolicy() (*riskapp.CustomPolicyCommands, error) {
	clock, ids := f.clockIDs()
	return riskapp.NewCustomPolicyCommands(riskapp.CustomPolicyCommandConfig{Authorizer: riskapp.NewCustomPolicyAuthorizer(), Transactions: riskWorkflowNativeFixtureTransactions{f.catalogFixtureCommands}, Hasher: riskWorkflowNativeFixtureHasher{}, Clock: clock, IDs: ids})
}
func (f riskWorkflowFixtureCommands) nativeWorkflow() (*riskapp.VulnerabilityWorkflowCommands, error) {
	clock, ids := f.clockIDs()
	return riskapp.NewVulnerabilityWorkflowCommands(riskapp.VulnerabilityWorkflowCommandConfig{Authorizer: riskapp.NewVulnerabilityWorkflowWriteAuthorizer(), Transactions: riskWorkflowNativeFixtureTransactions{f.catalogFixtureCommands}, Clock: clock, IDs: ids})
}
func (s *Server) bindRiskWorkflowFixtureResources(clock application.Clock, ids application.IDGenerator) {
	if f, ok := s.customPolicyCommands.(riskWorkflowFixtureCommands); ok {
		f.clock, f.ids = clock, ids
		s.customPolicyCommands = f
	}
	if f, ok := s.vulnerabilityWorkflowCommands.(riskWorkflowFixtureCommands); ok {
		f.clock, f.ids = clock, ids
		s.vulnerabilityWorkflowCommands = f
	}
}
