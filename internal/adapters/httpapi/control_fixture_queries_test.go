package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

// These test-only readers preserve former tenant/grant rules and detach
// mutable definition data. Runtime filtering/keyset limits remain in SQL.
type controlReadFixture struct{ catalogFixtureCommands }
type controlEvidencePageFixture struct{ catalogFixtureCommands }

func (f controlReadFixture) ListFrameworksPage(ctx context.Context, a domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[riskdomain.ControlFramework], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, err
	}
	values, err := f.commandLedger(ctx).ListControlFrameworks(ctx, a)
	if err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, err
	}
	items := make([]riskdomain.ControlFramework, 0, len(values))
	for _, v := range values {
		items = append(items, riskdomain.ControlFramework(v))
	}
	return appquery.Page(items, request, after, func(v riskdomain.ControlFramework, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(v.ID, v.CreatedAt, sort)
	})
}
func (f controlReadFixture) GetSecurityControl(ctx context.Context, a domain.Actor, id string) (riskdomain.SecurityControl, error) {
	v, err := f.commandLedger(ctx).GetSecurityControl(ctx, a, id)
	return fixtureSecurityControl(v), err
}
func (f controlReadFixture) ListTemplatePacks(ctx context.Context, a domain.Actor) ([]riskdomain.ControlFrameworkTemplatePack, error) {
	values, err := f.commandLedger(ctx).ListControlFrameworkTemplatePacks(ctx, a)
	if err != nil {
		return nil, err
	}
	items := make([]riskdomain.ControlFrameworkTemplatePack, 0, len(values))
	for _, v := range values {
		controls := make([]riskdomain.SecurityControl, 0, len(v.Controls))
		for _, control := range v.Controls {
			controls = append(controls, fixtureSecurityControl(control))
		}
		items = append(items, riskdomain.ControlFrameworkTemplatePack{ID: v.ID, Name: v.Name, Slug: v.Slug, Version: v.Version, Description: v.Description, Controls: controls, SchemaVersion: v.SchemaVersion})
	}
	return items, nil
}
func (f controlEvidencePageFixture) ListPage(ctx context.Context, a domain.Actor, filter riskquery.ControlEvidenceFilter, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[riskdomain.ControlEvidence], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[riskdomain.ControlEvidence]{}, err
	}
	values, err := f.commandLedger(ctx).ListControlEvidence(ctx, a, filter.ControlID, filter.ProductID, filter.ReleaseID)
	if err != nil {
		return appquery.Result[riskdomain.ControlEvidence]{}, err
	}
	items := make([]riskdomain.ControlEvidence, 0, len(values))
	for _, v := range values {
		items = append(items, riskdomain.ControlEvidence(v))
	}
	return appquery.Page(items, request, after, func(v riskdomain.ControlEvidence, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(v.ID, v.CreatedAt, sort)
	})
}
func (s *Server) bindControlFixtureQueries(ledger *app.Ledger) {
	f := catalogFixtureCommands{ledger: ledger}
	if _, fixture := s.controlsQuery.(controlReadFixture); s.controlsQuery == nil || fixture {
		s.controlsQuery = controlReadFixture{f}
	}
	if _, fixture := s.controlTemplateQuery.(controlReadFixture); s.controlTemplateQuery == nil || fixture {
		s.controlTemplateQuery = controlReadFixture{f}
	}
	if _, fixture := s.controlEvidenceQuery.(controlEvidencePageFixture); s.controlEvidenceQuery == nil || fixture {
		s.controlEvidenceQuery = controlEvidencePageFixture{f}
	}
}

var (
	_ ControlsQuery        = controlReadFixture{}
	_ ControlTemplateQuery = controlReadFixture{}
	_ ControlEvidenceQuery = controlEvidencePageFixture{}
)
