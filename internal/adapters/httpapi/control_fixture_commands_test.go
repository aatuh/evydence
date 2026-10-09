package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Historical HTTP tests alone use these bridges. Existing real guards check
// current fixture authority; real commands execute on the isolated replay
// clone. Runtime uses focused Risk transactions, not these maps or inventories.
type controlFixtureCommands struct{ catalogFixtureCommands }

func fixtureControlFrameworkInput(in riskapp.CreateControlFrameworkInput) app.CreateControlFrameworkInput {
	return app.CreateControlFrameworkInput(in)
}
func fixtureSecurityControlInput(in riskapp.CreateSecurityControlInput) app.CreateSecurityControlInput {
	requirements := make([]domain.ControlEvidenceRequirement, 0, len(in.EvidenceRequirements))
	for _, v := range in.EvidenceRequirements {
		requirements = append(requirements, domain.ControlEvidenceRequirement(v))
	}
	return app.CreateSecurityControlInput{FrameworkID: in.FrameworkID, Code: in.Code, Title: in.Title, Objective: in.Objective, EvidenceRequirements: requirements, Applicability: slices.Clone(in.Applicability), Limitations: slices.Clone(in.Limitations)}
}
func fixtureControlEvidenceInput(in riskapp.LinkControlEvidenceInput) app.LinkControlEvidenceInput {
	return app.LinkControlEvidenceInput(in)
}
func fixtureSecurityControl(v domain.SecurityControl) riskdomain.SecurityControl {
	requirements := make([]riskdomain.ControlEvidenceRequirement, 0, len(v.EvidenceRequirements))
	for _, value := range v.EvidenceRequirements {
		requirements = append(requirements, riskdomain.ControlEvidenceRequirement(value))
	}
	return riskdomain.SecurityControl{ID: v.ID, TenantID: v.TenantID, FrameworkID: v.FrameworkID, Code: v.Code, Title: v.Title, Objective: v.Objective, EvidenceRequirements: requirements, Applicability: slices.Clone(v.Applicability), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

func (f controlFixtureCommands) AuthorizeControlFrameworkCreation(ctx context.Context, a domain.Actor, in riskapp.CreateControlFrameworkInput) error {
	return f.commandLedger(ctx).AuthorizeControlFrameworkCreation(ctx, a, fixtureControlFrameworkInput(in))
}
func (f controlFixtureCommands) AuthorizeSecurityControlCreation(ctx context.Context, a domain.Actor, in riskapp.CreateSecurityControlInput) error {
	return f.commandLedger(ctx).AuthorizeSecurityControlCreation(ctx, a, fixtureSecurityControlInput(in))
}
func (f controlFixtureCommands) AuthorizeControlTemplateInstallation(ctx context.Context, a domain.Actor, slug string) error {
	return f.commandLedger(ctx).AuthorizeControlTemplateInstallation(ctx, a, slug)
}
func (f controlFixtureCommands) AuthorizeControlEvidenceLink(ctx context.Context, a domain.Actor, id string, in riskapp.LinkControlEvidenceInput) error {
	return f.commandLedger(ctx).AuthorizeControlEvidenceLink(ctx, a, id, fixtureControlEvidenceInput(in))
}
func (f controlFixtureCommands) CreateControlFramework(ctx context.Context, a domain.Actor, in riskapp.CreateControlFrameworkInput) (riskdomain.ControlFramework, error) {
	v, err := f.commandLedger(ctx).CreateControlFramework(ctx, a, fixtureControlFrameworkInput(in))
	return riskdomain.ControlFramework(v), err
}
func (f controlFixtureCommands) CreateSecurityControl(ctx context.Context, a domain.Actor, in riskapp.CreateSecurityControlInput) (riskdomain.SecurityControl, error) {
	v, err := f.commandLedger(ctx).CreateSecurityControl(ctx, a, fixtureSecurityControlInput(in))
	return fixtureSecurityControl(v), err
}
func (f controlFixtureCommands) InstallControlFrameworkTemplatePack(ctx context.Context, a domain.Actor, slug string) (riskdomain.ControlFramework, error) {
	v, err := f.commandLedger(ctx).InstallControlFrameworkTemplatePack(ctx, a, slug)
	return riskdomain.ControlFramework(v), err
}
func (f controlFixtureCommands) LinkControlEvidence(ctx context.Context, a domain.Actor, id string, in riskapp.LinkControlEvidenceInput) (riskdomain.ControlEvidence, error) {
	v, err := f.commandLedger(ctx).LinkControlEvidence(ctx, a, id, fixtureControlEvidenceInput(in))
	return riskdomain.ControlEvidence(v), err
}
func (s *Server) bindControlFixtureCommands(ledger *app.Ledger) {
	f := controlFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.controlCommands.(controlFixtureCommands); s.controlCommands == nil || fixture {
		s.controlCommands = f
	}
	if _, fixture := s.controlTemplateCommands.(controlFixtureCommands); s.controlTemplateCommands == nil || fixture {
		s.controlTemplateCommands = f
	}
	if _, fixture := s.controlEvidenceCommands.(controlFixtureCommands); s.controlEvidenceCommands == nil || fixture {
		s.controlEvidenceCommands = f
	}
}

var (
	_ ControlCommands         = controlFixtureCommands{}
	_ ControlTemplateCommands = controlFixtureCommands{}
	_ ControlEvidenceCommands = controlFixtureCommands{}
)
