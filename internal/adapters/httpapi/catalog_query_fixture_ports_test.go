package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// Product/candidate pages and catalog/build/candidate points run the actual
// focused query services on transaction-owned test readers. Other catalog surfaces
// still retain their historical fixtures; none is a production query adapter.
type catalogQueryFixture struct{ catalogFixtureCommands }

func (f catalogQueryFixture) ListProductsPage(ctx context.Context, actor domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[releasedomain.Product], error) {
	query, err := releasequery.NewProducts(catalogNativeFixtureReader(f), releasequery.NewCatalogAuthorizer())
	if err != nil {
		return appquery.Result[releasedomain.Product]{}, err
	}
	return query.ListProductsPage(ctx, actor, request, after)
}

func (f catalogQueryFixture) GetProduct(ctx context.Context, actor domain.Actor, id string) (releasedomain.Product, error) {
	query, err := releasequery.NewProducts(catalogNativeFixtureReader(f), releasequery.NewCatalogAuthorizer())
	if err != nil {
		return releasedomain.Product{}, err
	}
	return query.GetProduct(ctx, actor, id)
}

func (f catalogQueryFixture) GetProject(ctx context.Context, actor domain.Actor, id string) (releasedomain.Project, error) {
	query, err := releasequery.NewCatalogPoints(catalogNativeFixtureReader(f), releasequery.NewCatalogAuthorizer())
	if err != nil {
		return releasedomain.Project{}, err
	}
	return query.GetProject(ctx, actor, id)
}

func (f catalogQueryFixture) GetRelease(ctx context.Context, actor domain.Actor, id string) (releasedomain.Release, error) {
	query, err := releasequery.NewCatalogPoints(catalogNativeFixtureReader(f), releasequery.NewCatalogAuthorizer())
	if err != nil {
		return releasedomain.Release{}, err
	}
	return query.GetRelease(ctx, actor, id)
}

func (f catalogQueryFixture) GetArtifact(ctx context.Context, actor domain.Actor, id string) (releasedomain.Artifact, error) {
	value, err := f.commandLedger(ctx).GetArtifact(ctx, actor, id)
	return artifactFixtureModel(value), err
}

func (f catalogQueryFixture) GetBuildRun(ctx context.Context, actor domain.Actor, id string) (releasedomain.BuildRun, error) {
	query, err := releasequery.NewBuildPoints(catalogNativeFixtureReader(f), releasequery.NewCatalogAuthorizer())
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	return query.GetBuildRun(ctx, actor, id)
}

func (f catalogQueryFixture) GetReleaseCandidate(ctx context.Context, actor domain.Actor, id string) (releasedomain.ReleaseCandidate, error) {
	query, err := releasequery.NewReleaseCandidates(catalogNativeFixtureReader(f), releasequery.NewCatalogAuthorizer())
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	return query.GetReleaseCandidate(ctx, actor, id)
}

func (f catalogQueryFixture) ListPage(ctx context.Context, actor domain.Actor, releaseID string, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[releasedomain.ReleaseCandidate], error) {
	query, err := releasequery.NewReleaseCandidates(catalogNativeFixtureReader(f), releasequery.NewCatalogAuthorizer())
	if err != nil {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, err
	}
	return query.ListPage(ctx, actor, releaseID, request, after)
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
