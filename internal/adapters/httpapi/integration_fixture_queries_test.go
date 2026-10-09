package httpapi

import (
	"context"
	"slices"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

// Test-only readers retain real former tenant/grant checks and then paginate
// detached values. Native readers continue to filter and limit in SQL.
type collectorPageFixture struct{ catalogFixtureCommands }
type collectorHealthFixture struct{ catalogFixtureCommands }
type commercialCollectorPageFixture struct{ catalogFixtureCommands }
type sourceRepositoryPageFixture struct{ catalogFixtureCommands }

func fixtureCollector(v domain.Collector) (integrationdomain.Collector, error) {
	status, err := integrationdomain.ParseCollectorStatus(v.Status)
	var lastSeen *time.Time
	if v.LastSeenAt != nil {
		value := *v.LastSeenAt
		lastSeen = &value
	}
	return integrationdomain.Collector{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Type: v.Type, Version: v.Version, APIKeyID: v.APIKeyID, Status: status, AllowedScopes: slices.Clone(v.AllowedScopes), LastSeenAt: lastSeen, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, err
}
func (f collectorPageFixture) ListPage(ctx context.Context, a domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[integrationdomain.Collector], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[integrationdomain.Collector]{}, err
	}
	values, err := f.commandLedger(ctx).ListCollectors(ctx, a)
	if err != nil {
		return appquery.Result[integrationdomain.Collector]{}, err
	}
	items := make([]integrationdomain.Collector, 0, len(values))
	for _, v := range values {
		model, err := fixtureCollector(v)
		if err != nil {
			return appquery.Result[integrationdomain.Collector]{}, err
		}
		items = append(items, model)
	}
	return appquery.Page(items, request, after, func(v integrationdomain.Collector, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(v.ID, v.CreatedAt, sort)
	})
}
func (f commercialCollectorPageFixture) ListPage(ctx context.Context, a domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[integrationdomain.CommercialCollectorDefinition], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[integrationdomain.CommercialCollectorDefinition]{}, err
	}
	values, err := f.commandLedger(ctx).ListCommercialCollectorDefinitions(ctx, a)
	if err != nil {
		return appquery.Result[integrationdomain.CommercialCollectorDefinition]{}, err
	}
	items := make([]integrationdomain.CommercialCollectorDefinition, 0, len(values))
	for _, v := range values {
		model := integrationdomain.CommercialCollectorDefinition(v)
		model.AllowedScopes = slices.Clone(v.AllowedScopes)
		items = append(items, model)
	}
	return appquery.Page(items, request, after, func(v integrationdomain.CommercialCollectorDefinition, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(v.ID, v.CreatedAt, sort)
	})
}
func (f sourceRepositoryPageFixture) ListPage(ctx context.Context, a domain.Actor, project string, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[integrationdomain.SourceRepository], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[integrationdomain.SourceRepository]{}, err
	}
	values, err := f.commandLedger(ctx).ListSourceRepositories(ctx, a, project)
	if err != nil {
		return appquery.Result[integrationdomain.SourceRepository]{}, err
	}
	items := make([]integrationdomain.SourceRepository, 0, len(values))
	for _, v := range values {
		items = append(items, integrationdomain.SourceRepository(v))
	}
	return appquery.Page(items, request, after, func(v integrationdomain.SourceRepository, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(v.ID, v.CreatedAt, sort)
	})
}
func (f collectorHealthFixture) Report(ctx context.Context, a domain.Actor, id string) (integrationdomain.CollectorHealthReport, error) {
	v, err := f.commandLedger(ctx).CollectorHealthReport(ctx, a, id)
	checks := make([]integrationdomain.VerificationCheck, 0, len(v.Checks))
	for _, check := range v.Checks {
		checks = append(checks, integrationdomain.VerificationCheck(check))
	}
	var latest *integrationdomain.CollectorRelease
	if v.LatestRelease != nil {
		model := integrationdomain.CollectorRelease(*v.LatestRelease)
		model.Limitations = slices.Clone(v.LatestRelease.Limitations)
		latest = &model
	}
	return integrationdomain.CollectorHealthReport{ReportType: v.ReportType, CollectorID: v.CollectorID, CollectorStatus: v.CollectorStatus, Version: v.Version, PinnedReleaseID: v.PinnedReleaseID, SupplyChainStatus: v.SupplyChainStatus, Checks: checks, LatestRelease: latest, Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), GeneratedAt: v.GeneratedAt}, err
}
func (s *Server) bindIntegrationFixtureQueries(ledger *app.Ledger) {
	f := catalogFixtureCommands{ledger: ledger}
	if _, fixture := s.collectorQuery.(collectorPageFixture); s.collectorQuery == nil || fixture {
		s.collectorQuery = collectorPageFixture{f}
	}
	if _, fixture := s.collectorHealthQuery.(collectorHealthFixture); s.collectorHealthQuery == nil || fixture {
		s.collectorHealthQuery = collectorHealthFixture{f}
	}
	if _, fixture := s.commercialCollectorQuery.(commercialCollectorPageFixture); s.commercialCollectorQuery == nil || fixture {
		s.commercialCollectorQuery = commercialCollectorPageFixture{f}
	}
	if _, fixture := s.sourceRepositoryQuery.(sourceRepositoryPageFixture); s.sourceRepositoryQuery == nil || fixture {
		s.sourceRepositoryQuery = sourceRepositoryPageFixture{f}
	}
}

var (
	_ CollectorQuery           = collectorPageFixture{}
	_ CollectorHealthQuery     = collectorHealthFixture{}
	_ CommercialCollectorQuery = commercialCollectorPageFixture{}
	_ SourceRepositoryQuery    = sourceRepositoryPageFixture{}
)
