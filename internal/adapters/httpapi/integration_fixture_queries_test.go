package httpapi

import (
	"context"
	"slices"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

// Test-only readers retain real former tenant/grant checks and then paginate
// detached values. Native readers continue to filter and limit in SQL.
type collectorPageFixture struct{ catalogFixtureCommands }
type collectorHealthFixture struct {
	catalogFixtureCommands
	now func() time.Time
}
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
	q, err := integrationquery.NewCollectors(f)
	if err != nil {
		return appquery.Result[integrationdomain.Collector]{}, err
	}
	v, err := q.ListPage(ctx, a, request, after)
	return v, mapIntegrationQueryError(err)
}
func (f collectorPageFixture) PageCollectors(ctx context.Context, request integrationquery.CollectorPageRequest) (appquery.Result[integrationdomain.Collector], error) {
	var out appquery.Result[integrationdomain.Collector]
	if ctx == nil {
		return out, integrationquery.ErrValidation
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Builds.(integrationquery.CollectorReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.PageCollectors(ctx, request)
		return err
	})
	if err != nil {
		return appquery.Result[integrationdomain.Collector]{}, err
	}
	return out, nil
}
func (f commercialCollectorPageFixture) ListPage(ctx context.Context, a domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[integrationdomain.CommercialCollectorDefinition], error) {
	q, err := integrationquery.NewCommercialCollectors(f)
	if err != nil {
		return appquery.Result[integrationdomain.CommercialCollectorDefinition]{}, err
	}
	v, err := q.ListPage(ctx, a, request, after)
	return v, mapIntegrationQueryError(err)
}
func (f commercialCollectorPageFixture) PageCommercialCollectors(ctx context.Context, request integrationquery.CommercialCollectorPageRequest) (appquery.Result[integrationdomain.CommercialCollectorDefinition], error) {
	var out appquery.Result[integrationdomain.CommercialCollectorDefinition]
	if ctx == nil {
		return out, integrationquery.ErrValidation
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Enterprise.(integrationquery.CommercialCollectorReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.PageCommercialCollectors(ctx, request)
		return err
	})
	if err != nil {
		return appquery.Result[integrationdomain.CommercialCollectorDefinition]{}, err
	}
	return out, nil
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
	now := f.now
	if now == nil {
		now = time.Now
	}
	query, err := integrationquery.NewCollectorHealth(f, now)
	if err != nil {
		return integrationdomain.CollectorHealthReport{}, err
	}
	v, err := query.Report(ctx, a, id)
	return v, mapIntegrationQueryError(err)
}
func (f collectorHealthFixture) GetCollectorHealthPoint(ctx context.Context, tenant, id string) (integrationquery.CollectorHealthPoint, error) {
	var out integrationquery.CollectorHealthPoint
	if ctx == nil {
		return out, integrationquery.ErrValidation
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Builds.(integrationquery.CollectorHealthReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.GetCollectorHealthPoint(ctx, tenant, id)
		return err
	})
	if err != nil {
		return integrationquery.CollectorHealthPoint{}, err
	}
	return out, nil
}
func (s *Server) bindIntegrationFixtureQueries(ledger *app.Ledger) {
	f := catalogFixtureCommands{ledger: ledger}
	if _, fixture := s.collectorQuery.(collectorPageFixture); s.collectorQuery == nil || fixture {
		s.collectorQuery = collectorPageFixture{f}
	}
	if old, fixture := s.collectorHealthQuery.(collectorHealthFixture); fixture {
		old.ledger = ledger
		s.collectorHealthQuery = old
	} else if s.collectorHealthQuery == nil {
		s.collectorHealthQuery = collectorHealthFixture{catalogFixtureCommands: f}
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
