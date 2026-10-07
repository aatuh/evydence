package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Test-only preflight runs the real focused guard algorithms against actual
// transaction-owned references. It cannot read policy rules, evidence content,
// historical reasons, hashes or clocks, allocate IDs or perform effects.
type riskWorkflowFixtureTransactions struct{ catalogFixtureCommands }
type riskWorkflowFixtureGuard struct {
	owners   riskapp.WaiverCommandReader
	tenants  identityapp.APIKeyWriteReader
	workflow riskapp.VulnerabilityWorkflowReader
}

func (f riskWorkflowFixtureTransactions) execute(ctx context.Context, run func(context.Context, riskWorkflowFixtureGuard) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		owners, ok := repos.Governance.(riskapp.WaiverCommandReader)
		if !ok {
			return app.ErrValidation
		}
		tenants, ok := repos.Identity.(identityapp.APIKeyWriteReader)
		if !ok {
			return app.ErrValidation
		}
		workflow, ok := repos.Risk.(riskapp.VulnerabilityWorkflowReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, riskWorkflowFixtureGuard{owners: owners, tenants: tenants, workflow: workflow})
	})
}
func (f riskWorkflowFixtureTransactions) ExecuteCustomPolicy(ctx context.Context, run func(context.Context, riskapp.CustomPolicyTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx riskWorkflowFixtureGuard) error { return run(ctx, tx) })
}
func (f riskWorkflowFixtureTransactions) ExecuteVulnerabilityWorkflow(ctx context.Context, run func(context.Context, riskapp.VulnerabilityWorkflowTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx riskWorkflowFixtureGuard) error { return run(ctx, tx) })
}
func (g riskWorkflowFixtureGuard) PolicyTenantExists(ctx context.Context, tenant string) (bool, error) {
	// This existing memory capability checks actual tenant presence without
	// reading credentials. Its optimistic snapshot is not a PostgreSQL lock.
	err := g.tenants.LockAPIKeyCreation(ctx, tenant)
	if errors.Is(err, app.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
func (g riskWorkflowFixtureGuard) ReadCustomPolicySubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	return g.owners.ReadWaiverSubject(ctx, tenant, kind, id)
}
func (g riskWorkflowFixtureGuard) ReadWorkflowFinding(ctx context.Context, tenant, id string) (riskapp.GovernanceSubjectReference, error) {
	return g.workflow.ReadWorkflowFinding(ctx, tenant, id)
}
func (riskWorkflowFixtureGuard) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	if r.Scope == "security:write" {
		return riskapp.NewVulnerabilityWorkflowWriteAuthorizer().Authorize(ctx, a, r)
	}
	return riskapp.NewCustomPolicyAuthorizer().Authorize(ctx, a, r)
}
func (riskWorkflowFixtureGuard) ReadCustomPolicy(context.Context, string, string) (riskdomain.CustomPolicy, error) {
	panic("Risk replay guard read policy definition")
}
func (riskWorkflowFixtureGuard) ReadCustomPolicyEvidencePresence(context.Context, string, string, []string) (map[string]bool, error) {
	panic("Risk replay guard read evidence presence")
}
func (riskWorkflowFixtureGuard) InsertCustomPolicy(context.Context, riskdomain.CustomPolicy) error {
	panic("Risk replay guard inserted policy")
}
func (riskWorkflowFixtureGuard) InsertCustomPolicyEvaluation(context.Context, riskdomain.CustomPolicyEvaluation) error {
	panic("Risk replay guard inserted evaluation")
}
func (riskWorkflowFixtureGuard) InsertVulnerabilityWorkflow(context.Context, riskdomain.VulnerabilityWorkflowRecord) error {
	panic("Risk replay guard inserted workflow")
}
func (riskWorkflowFixtureGuard) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("Risk replay guard appended audit")
}
func (riskWorkflowFixtureGuard) HashCustomPolicy(riskdomain.CustomPolicy, string, []riskdomain.PolicyCheck) (string, error) {
	panic("Risk replay guard hashed policy")
}
func riskWorkflowFixtureGuardClock() time.Time { panic("Risk replay guard read clock") }
func riskWorkflowFixtureGuardID(string) string { panic("Risk replay guard allocated ID") }

func (f riskWorkflowFixtureCommands) policyGuard() (*riskapp.CustomPolicyCommands, error) {
	return riskapp.NewCustomPolicyCommands(riskapp.CustomPolicyCommandConfig{Authorizer: riskapp.NewCustomPolicyAuthorizer(), Transactions: riskWorkflowFixtureTransactions(f), Hasher: riskWorkflowFixtureGuard{}, Clock: application.ClockFunc(riskWorkflowFixtureGuardClock), IDs: application.IDGeneratorFunc(riskWorkflowFixtureGuardID)})
}
func (f riskWorkflowFixtureCommands) workflowGuard() (*riskapp.VulnerabilityWorkflowCommands, error) {
	return riskapp.NewVulnerabilityWorkflowCommands(riskapp.VulnerabilityWorkflowCommandConfig{Authorizer: riskapp.NewVulnerabilityWorkflowWriteAuthorizer(), Transactions: riskWorkflowFixtureTransactions(f), Clock: application.ClockFunc(riskWorkflowFixtureGuardClock), IDs: application.IDGeneratorFunc(riskWorkflowFixtureGuardID)})
}
func (f riskWorkflowFixtureCommands) AuthorizeCreateCustomPolicy(ctx context.Context, a domain.Actor, in riskapp.CreateCustomPolicyInput) error {
	g, err := f.policyGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeCreateCustomPolicy(ctx, a, in)
}
func (f riskWorkflowFixtureCommands) AuthorizeEvaluateCustomPolicy(ctx context.Context, a domain.Actor, policy, release string) error {
	g, err := f.policyGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeEvaluateCustomPolicy(ctx, a, policy, release)
}
func (f riskWorkflowFixtureCommands) AuthorizeVulnerabilityWorkflow(ctx context.Context, a domain.Actor, in riskapp.RecordVulnerabilityWorkflowInput) error {
	g, err := f.workflowGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeVulnerabilityWorkflow(ctx, a, in)
}
