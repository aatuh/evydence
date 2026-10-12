package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Historical HTTP tests alone use these bridges. Existing real guards check
// current fixture authority; real commands execute on the isolated replay
// clone. Runtime uses focused Risk transactions, not these maps or inventories.
type controlFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}

func fixtureSecurityControl(v domain.SecurityControl) riskdomain.SecurityControl {
	requirements := make([]riskdomain.ControlEvidenceRequirement, 0, len(v.EvidenceRequirements))
	for _, value := range v.EvidenceRequirements {
		requirements = append(requirements, riskdomain.ControlEvidenceRequirement(value))
	}
	return riskdomain.SecurityControl{ID: v.ID, TenantID: v.TenantID, FrameworkID: v.FrameworkID, Code: v.Code, Title: v.Title, Objective: v.Objective, EvidenceRequirements: requirements, Applicability: slices.Clone(v.Applicability), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

func (f controlFixtureCommands) AuthorizeControlFrameworkCreation(ctx context.Context, a domain.Actor, in riskapp.CreateControlFrameworkInput) error {
	c, err := f.nativeControls(true)
	if err != nil {
		return err
	}
	return mapControlCommandError(c.AuthorizeControlFrameworkCreation(ctx, a, in))
}
func (f controlFixtureCommands) AuthorizeSecurityControlCreation(ctx context.Context, a domain.Actor, in riskapp.CreateSecurityControlInput) error {
	c, err := f.nativeControls(true)
	if err != nil {
		return err
	}
	return mapControlCommandError(c.AuthorizeSecurityControlCreation(ctx, a, in))
}
func (f controlFixtureCommands) AuthorizeControlTemplateInstallation(ctx context.Context, a domain.Actor, slug string) error {
	c, err := f.nativeTemplate(true)
	if err != nil {
		return err
	}
	return mapControlCommandError(c.AuthorizeControlTemplateInstallation(ctx, a, slug))
}
func (f controlFixtureCommands) AuthorizeControlEvidenceLink(ctx context.Context, a domain.Actor, id string, in riskapp.LinkControlEvidenceInput) error {
	c, err := f.nativeLink(true)
	if err != nil {
		return err
	}
	return mapControlCommandError(c.AuthorizeControlEvidenceLink(ctx, a, id, in))
}
func (f controlFixtureCommands) CreateControlFramework(ctx context.Context, a domain.Actor, in riskapp.CreateControlFrameworkInput) (riskdomain.ControlFramework, error) {
	c, err := f.nativeControls(false)
	if err != nil {
		return riskdomain.ControlFramework{}, err
	}
	v, err := c.CreateControlFramework(ctx, a, in)
	return v, mapControlCommandError(err)
}
func (f controlFixtureCommands) CreateSecurityControl(ctx context.Context, a domain.Actor, in riskapp.CreateSecurityControlInput) (riskdomain.SecurityControl, error) {
	c, err := f.nativeControls(false)
	if err != nil {
		return riskdomain.SecurityControl{}, err
	}
	v, err := c.CreateSecurityControl(ctx, a, in)
	return v, mapControlCommandError(err)
}
func (f controlFixtureCommands) InstallControlFrameworkTemplatePack(ctx context.Context, a domain.Actor, slug string) (riskdomain.ControlFramework, error) {
	c, err := f.nativeTemplate(false)
	if err != nil {
		return riskdomain.ControlFramework{}, err
	}
	v, err := c.InstallControlFrameworkTemplatePack(ctx, a, slug)
	return v, mapControlCommandError(err)
}
func (f controlFixtureCommands) LinkControlEvidence(ctx context.Context, a domain.Actor, id string, in riskapp.LinkControlEvidenceInput) (riskdomain.ControlEvidence, error) {
	c, err := f.nativeLink(false)
	if err != nil {
		return riskdomain.ControlEvidence{}, err
	}
	v, err := c.LinkControlEvidence(ctx, a, id, in)
	return v, mapControlCommandError(err)
}
func (s *Server) bindControlFixtureCommands(ledger *repositoryFixture) {
	f := controlFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, fixture := s.controlCommands.(controlFixtureCommands); fixture {
		old.ledger = ledger
		s.controlCommands = old
	} else if s.controlCommands == nil {
		s.controlCommands = f
	}
	if old, fixture := s.controlTemplateCommands.(controlFixtureCommands); fixture {
		old.ledger = ledger
		s.controlTemplateCommands = old
	} else if s.controlTemplateCommands == nil {
		s.controlTemplateCommands = f
	}
	if old, fixture := s.controlEvidenceCommands.(controlFixtureCommands); fixture {
		old.ledger = ledger
		s.controlEvidenceCommands = old
	} else if s.controlEvidenceCommands == nil {
		s.controlEvidenceCommands = f
	}
}

var (
	_ ControlCommands         = controlFixtureCommands{}
	_ ControlTemplateCommands = controlFixtureCommands{}
	_ ControlEvidenceCommands = controlFixtureCommands{}
)
