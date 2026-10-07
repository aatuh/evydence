package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// These are in-memory HTTP test readers, never production query adapters.
// Authorization/filtering stays on the real fixture service; production reads
// remain bounded PostgreSQL queries rather than aggregate map scans.
type catalogQueryFixture struct{ catalogFixtureCommands }

func (f catalogQueryFixture) ListProductsPage(ctx context.Context, actor domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[releasedomain.Product], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[releasedomain.Product]{}, err
	}
	values, err := f.commandLedger(ctx).ListProducts(ctx, actor)
	if err != nil {
		return appquery.Result[releasedomain.Product]{}, err
	}
	items := make([]releasedomain.Product, 0, len(values))
	for _, value := range values {
		items = append(items, releasedomain.Product{ID: value.ID, TenantID: value.TenantID, Name: value.Name, Slug: value.Slug, CreatedAt: value.CreatedAt})
	}
	return appquery.Page(items, request, after, func(value releasedomain.Product, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(value.ID, value.CreatedAt, sort)
	})
}

func (f catalogQueryFixture) GetProduct(ctx context.Context, actor domain.Actor, id string) (releasedomain.Product, error) {
	value, err := f.commandLedger(ctx).GetProduct(ctx, actor, id)
	return releasedomain.Product{ID: value.ID, TenantID: value.TenantID, Name: value.Name, Slug: value.Slug, CreatedAt: value.CreatedAt}, err
}

func (f catalogQueryFixture) GetProject(ctx context.Context, actor domain.Actor, id string) (releasedomain.Project, error) {
	value, err := f.commandLedger(ctx).GetProject(ctx, actor, id)
	return releasedomain.Project{ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, Name: value.Name, CreatedAt: value.CreatedAt}, err
}

func (f catalogQueryFixture) GetRelease(ctx context.Context, actor domain.Actor, id string) (releasedomain.Release, error) {
	value, err := f.commandLedger(ctx).GetRelease(ctx, actor, id)
	if err != nil {
		return releasedomain.Release{}, err
	}
	return releaseFixtureModel(value)
}

func (f catalogQueryFixture) GetArtifact(ctx context.Context, actor domain.Actor, id string) (releasedomain.Artifact, error) {
	value, err := f.commandLedger(ctx).GetArtifact(ctx, actor, id)
	return artifactFixtureModel(value), err
}

func (f catalogQueryFixture) GetBuildRun(ctx context.Context, actor domain.Actor, id string) (releasedomain.BuildRun, error) {
	value, err := f.commandLedger(ctx).GetBuildRun(ctx, actor, id)
	return buildFixtureModel(value), err
}

func (f catalogQueryFixture) GetReleaseCandidate(ctx context.Context, actor domain.Actor, id string) (releasedomain.ReleaseCandidate, error) {
	value, err := f.commandLedger(ctx).GetReleaseCandidate(ctx, actor, id)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	return candidateFixtureModel(value)
}

func (f catalogQueryFixture) ListPage(ctx context.Context, actor domain.Actor, releaseID string, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[releasedomain.ReleaseCandidate], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, err
	}
	values, err := f.commandLedger(ctx).ListReleaseCandidates(ctx, actor, releaseID)
	if err != nil {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, err
	}
	items := make([]releasedomain.ReleaseCandidate, 0, len(values))
	for _, value := range values {
		item, err := candidateFixtureModel(value)
		if err != nil {
			return appquery.Result[releasedomain.ReleaseCandidate]{}, err
		}
		items = append(items, item)
	}
	return appquery.Page(items, request, after, func(value releasedomain.ReleaseCandidate, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(value.ID, value.CreatedAt, sort)
	})
}

func (f catalogQueryFixture) Plan(ctx context.Context, actor domain.Actor, id string) (releasedomain.ReleaseEvidenceFlow, error) {
	value, err := f.commandLedger(ctx).ReleaseEvidenceFlowPlan(ctx, actor, id)
	if err != nil {
		return releasedomain.ReleaseEvidenceFlow{}, err
	}
	steps := make([]releasedomain.ReleaseEvidenceFlowStep, 0, len(value.Steps))
	for _, step := range value.Steps {
		steps = append(steps, releasedomain.ReleaseEvidenceFlowStep{ID: step.ID, Title: step.Title, Status: step.Status, Required: step.Required, Method: step.Method, Path: step.Path, RequiredScopes: step.RequiredScopes, IdempotencyRequired: step.IdempotencyRequired, Description: step.Description, NextReference: step.NextReference})
	}
	return releasedomain.ReleaseEvidenceFlow{ReleaseID: value.ReleaseID, ProductID: value.ProductID, Status: value.Status, Counts: value.Counts, Steps: steps, Assumptions: value.Assumptions, Limitations: value.Limitations, SchemaVersion: value.SchemaVersion, GeneratedAt: value.GeneratedAt}, nil
}

func (s *Server) bindCatalogQueryFixturePorts(ledger *app.Ledger) {
	query := catalogQueryFixture{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.productQuery.(catalogQueryFixture); s.productQuery == nil || fixture {
		s.productQuery = query
	}
	if _, fixture := s.catalogPointQuery.(catalogQueryFixture); s.catalogPointQuery == nil || fixture {
		s.catalogPointQuery = query
	}
	if _, fixture := s.evidenceFlowQuery.(catalogQueryFixture); s.evidenceFlowQuery == nil || fixture {
		s.evidenceFlowQuery = query
	}
	if _, fixture := s.artifactPointQuery.(catalogQueryFixture); s.artifactPointQuery == nil || fixture {
		s.artifactPointQuery = query
	}
	if _, fixture := s.buildPointQuery.(catalogQueryFixture); s.buildPointQuery == nil || fixture {
		s.buildPointQuery = query
	}
	if _, fixture := s.releaseCandidateQuery.(catalogQueryFixture); s.releaseCandidateQuery == nil || fixture {
		s.releaseCandidateQuery = query
	}
}

var (
	_ ProductQuery          = catalogQueryFixture{}
	_ CatalogPointQuery     = catalogQueryFixture{}
	_ EvidenceFlowQuery     = catalogQueryFixture{}
	_ ArtifactPointQuery    = catalogQueryFixture{}
	_ BuildPointQuery       = catalogQueryFixture{}
	_ ReleaseCandidateQuery = catalogQueryFixture{}
)
