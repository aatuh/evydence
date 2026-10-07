package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Historical commands execute only on the test replay executor's isolated
// clone. Production transport always uses focused Risk transaction services.
type riskWorkflowFixtureCommands struct{ catalogFixtureCommands }

func (f riskWorkflowFixtureCommands) CreateCustomPolicy(ctx context.Context, a domain.Actor, in riskapp.CreateCustomPolicyInput) (riskdomain.CustomPolicy, error) {
	rules := make([]domain.PolicyRule, 0, len(in.Rules))
	for _, rule := range in.Rules {
		rules = append(rules, domain.PolicyRule(rule))
	}
	v, err := f.commandLedger(ctx).CreateCustomPolicy(ctx, a, app.CreateCustomPolicyInput{Name: in.Name, Version: in.Version, Description: in.Description, Rules: rules})
	return domain.CustomPolicyToContext(v), err
}
func (f riskWorkflowFixtureCommands) EvaluateCustomPolicy(ctx context.Context, a domain.Actor, policy, release string) (riskdomain.CustomPolicyEvaluation, error) {
	v, err := f.commandLedger(ctx).EvaluateCustomPolicy(ctx, a, policy, release)
	checks := make([]riskdomain.PolicyCheck, 0, len(v.Checks))
	for _, check := range v.Checks {
		checks = append(checks, riskdomain.PolicyCheck{Name: check.Name, Result: check.Result, Severity: check.Severity, Missing: slices.Clone(check.Missing), Explanation: check.Explanation, Remediation: check.Remediation})
	}
	return riskdomain.CustomPolicyEvaluation{ID: v.ID, TenantID: v.TenantID, PolicyID: v.PolicyID, ReleaseID: v.ReleaseID, Result: v.Result, Checks: checks, InputHash: v.InputHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, err
}
func (f riskWorkflowFixtureCommands) RecordVulnerabilityWorkflow(ctx context.Context, a domain.Actor, in riskapp.RecordVulnerabilityWorkflowInput) (riskdomain.VulnerabilityWorkflowRecord, error) {
	v, err := f.commandLedger(ctx).RecordVulnerabilityWorkflow(ctx, a, app.RecordVulnerabilityWorkflowInput(in))
	return riskdomain.VulnerabilityWorkflowRecord(v), err
}
func (s *Server) bindRiskWorkflowFixtureCommands(ledger *app.Ledger) {
	f := riskWorkflowFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.customPolicyCommands.(riskWorkflowFixtureCommands); s.customPolicyCommands == nil || fixture {
		s.customPolicyCommands = f
	}
	if _, fixture := s.vulnerabilityWorkflowCommands.(riskWorkflowFixtureCommands); s.vulnerabilityWorkflowCommands == nil || fixture {
		s.vulnerabilityWorkflowCommands = f
	}
}

var (
	_ CustomPolicyCommands          = riskWorkflowFixtureCommands{}
	_ VulnerabilityWorkflowCommands = riskWorkflowFixtureCommands{}
)
