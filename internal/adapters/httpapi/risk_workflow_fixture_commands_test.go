package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Actual Risk services run on the fixture's transaction-owned repositories.
// The historical replay executor still supplies its isolated command context.
type riskWorkflowFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
	ids   application.IDGenerator
}

func (f riskWorkflowFixtureCommands) CreateCustomPolicy(ctx context.Context, a domain.Actor, in riskapp.CreateCustomPolicyInput) (riskdomain.CustomPolicy, error) {
	commands, err := f.nativePolicy()
	if err != nil {
		return riskdomain.CustomPolicy{}, err
	}
	return commands.CreateCustomPolicy(ctx, a, in)
}
func (f riskWorkflowFixtureCommands) EvaluateCustomPolicy(ctx context.Context, a domain.Actor, policy, release string) (riskdomain.CustomPolicyEvaluation, error) {
	commands, err := f.nativePolicy()
	if err != nil {
		return riskdomain.CustomPolicyEvaluation{}, err
	}
	return commands.EvaluateCustomPolicy(ctx, a, policy, release)
}
func (f riskWorkflowFixtureCommands) RecordVulnerabilityWorkflow(ctx context.Context, a domain.Actor, in riskapp.RecordVulnerabilityWorkflowInput) (riskdomain.VulnerabilityWorkflowRecord, error) {
	commands, err := f.nativeWorkflow()
	if err != nil {
		return riskdomain.VulnerabilityWorkflowRecord{}, err
	}
	return commands.RecordVulnerabilityWorkflow(ctx, a, in)
}
func (s *Server) bindRiskWorkflowFixtureCommands(ledger *app.Ledger) {
	if f, fixture := s.customPolicyCommands.(riskWorkflowFixtureCommands); s.customPolicyCommands == nil || fixture {
		f.catalogFixtureCommands = catalogFixtureCommands{ledger: ledger}
		s.customPolicyCommands = f
	}
	if f, fixture := s.vulnerabilityWorkflowCommands.(riskWorkflowFixtureCommands); s.vulnerabilityWorkflowCommands == nil || fixture {
		f.catalogFixtureCommands = catalogFixtureCommands{ledger: ledger}
		s.vulnerabilityWorkflowCommands = f
	}
}

var (
	_ CustomPolicyCommands          = riskWorkflowFixtureCommands{}
	_ VulnerabilityWorkflowCommands = riskWorkflowFixtureCommands{}
)
