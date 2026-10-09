package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

// Framework pages and control points compose the actual focused query over
// current typed repositories. Link/catalog retirement remains separate work.
type controlReadFixture struct{ catalogFixtureCommands }
type controlEvidencePageFixture struct{ catalogFixtureCommands }

func (f controlReadFixture) ListFrameworksPage(ctx context.Context, a domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[riskdomain.ControlFramework], error) {
	query, err := riskquery.NewControls(f)
	if err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, err
	}
	v, err := query.ListFrameworksPage(ctx, a, request, after)
	return v, mapControlsQueryError(err)
}
func (f controlReadFixture) GetSecurityControl(ctx context.Context, a domain.Actor, id string) (riskdomain.SecurityControl, error) {
	query, err := riskquery.NewControls(f)
	if err != nil {
		return riskdomain.SecurityControl{}, err
	}
	v, err := query.GetSecurityControl(ctx, a, id)
	return v, mapControlsQueryError(err)
}
func (f controlReadFixture) PageFrameworks(ctx context.Context, req riskquery.FrameworkPageRequest) (appquery.Result[riskdomain.ControlFramework], error) {
	var out appquery.Result[riskdomain.ControlFramework]
	if ctx == nil {
		return out, riskquery.ErrValidation
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Controls.(riskquery.ControlsReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.PageFrameworks(ctx, req)
		return err
	})
	if err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, err
	}
	return out, nil
}
func (f controlReadFixture) GetControl(ctx context.Context, tenant, id string) (riskdomain.SecurityControl, error) {
	var out riskdomain.SecurityControl
	if ctx == nil {
		return out, riskquery.ErrValidation
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Controls.(riskquery.ControlsReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.GetControl(ctx, tenant, id)
		return err
	})
	if err != nil {
		return riskdomain.SecurityControl{}, err
	}
	return out, nil
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
	query, err := riskquery.NewControlEvidence(f)
	if err != nil {
		return appquery.Result[riskdomain.ControlEvidence]{}, err
	}
	v, err := query.ListPage(ctx, a, filter, request, after)
	return v, mapControlsQueryError(err)
}
func (f controlEvidencePageFixture) PageControlEvidence(ctx context.Context, req riskquery.ControlEvidencePageRequest) (appquery.Result[riskquery.ControlEvidencePoint], error) {
	var out appquery.Result[riskquery.ControlEvidencePoint]
	if ctx == nil {
		return out, riskquery.ErrValidation
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Controls.(riskquery.ControlEvidenceReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.PageControlEvidence(ctx, req)
		return err
	})
	if err != nil {
		return appquery.Result[riskquery.ControlEvidencePoint]{}, err
	}
	return out, nil
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
