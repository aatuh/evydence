package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

// Historical report fixtures retain actual former owned read/grant rules and
// detach mutable metadata. Runtime readers remain bounded SQL projections.
type packageCoverageFixture struct {
	catalogFixtureCommands
	clock func() time.Time
}
type packageHandlingFixture struct {
	catalogFixtureCommands
	clock func() time.Time
}
type packageUpdateFixture struct {
	catalogFixtureCommands
	clock func() time.Time
}
type packageBundleReadFixture struct{ catalogFixtureCommands }
type packageMissingFixture struct {
	catalogFixtureCommands
	clock func() time.Time
}

func (f packageCoverageFixture) Coverage(ctx context.Context, a domain.Actor, filter packagequery.ControlCoverageFilter) (packagedomain.ControlCoverageReport, error) {
	query, err := packagequery.NewControlCoverageReport(f, f.now)
	if err != nil {
		return packagedomain.ControlCoverageReport{}, err
	}
	return query.Coverage(ctx, a, filter)
}
func (f packageCoverageFixture) CRAReadiness(ctx context.Context, a domain.Actor, product, release string) (packagedomain.CRAReadinessReport, error) {
	query, err := packagequery.NewControlCoverageReport(f, f.now)
	if err != nil {
		return packagedomain.CRAReadinessReport{}, err
	}
	return query.CRAReadiness(ctx, a, product, release)
}
func (f packageHandlingFixture) Report(ctx context.Context, a domain.Actor, product, release string) (packagedomain.CRAVulnerabilityHandlingReport, error) {
	query, err := packagequery.NewCRAVulnerabilityHandling(f, f.now)
	if err != nil {
		return packagedomain.CRAVulnerabilityHandlingReport{}, err
	}
	return query.Report(ctx, a, product, release)
}
func (f packageUpdateFixture) Report(ctx context.Context, a domain.Actor, product, release string) (packagedomain.SecurityUpdateEvidenceReport, error) {
	query, err := packagequery.NewSecurityUpdateEvidence(f, f.now)
	if err != nil {
		return packagedomain.SecurityUpdateEvidenceReport{}, err
	}
	return query.Report(ctx, a, product, release)
}
func (f packageBundleReadFixture) GetReleaseBundle(ctx context.Context, a domain.Actor, id string) (packagedomain.ReleaseBundle, error) {
	query, err := packagequery.NewReleaseBundles(f)
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	return query.GetReleaseBundle(ctx, a, id)
}

// Compose the actual read-only Risk query and the native Package renderer.
// Neither authorization nor evaluation consults aggregate report caches.
func (f packageMissingFixture) Preview(ctx context.Context, a domain.Actor, id string) (riskdomain.PolicyEvaluation, error) {
	query, err := riskquery.NewReleaseReadinessQuery(f, f.now)
	if err != nil {
		return riskdomain.PolicyEvaluation{}, err
	}
	return query.Preview(ctx, a, id)
}
func (f packageMissingFixture) Report(ctx context.Context, a domain.Actor, id string) (map[string]any, error) {
	renderer, err := packagequery.NewMissingEvidenceReport(f)
	if err != nil {
		return nil, err
	}
	return renderer.Report(ctx, a, id)
}
func (s *Server) bindPackageReportFixtureQueries(ledger *app.Ledger) {
	f := catalogFixtureCommands{ledger: ledger}
	if query, fixture := s.controlCoverageQuery.(packageCoverageFixture); s.controlCoverageQuery == nil || fixture {
		query.catalogFixtureCommands = f
		s.controlCoverageQuery = query
	}
	if query, fixture := s.craVulnerabilityQuery.(packageHandlingFixture); s.craVulnerabilityQuery == nil || fixture {
		query.catalogFixtureCommands = f
		s.craVulnerabilityQuery = query
	}
	if query, fixture := s.securityUpdateEvidenceQuery.(packageUpdateFixture); s.securityUpdateEvidenceQuery == nil || fixture {
		query.catalogFixtureCommands = f
		s.securityUpdateEvidenceQuery = query
	}
	if _, fixture := s.releaseBundleQuery.(packageBundleReadFixture); s.releaseBundleQuery == nil || fixture {
		s.releaseBundleQuery = packageBundleReadFixture{f}
	}
	if query, fixture := s.missingEvidenceQuery.(packageMissingFixture); s.missingEvidenceQuery == nil || fixture {
		query.catalogFixtureCommands = f
		s.missingEvidenceQuery = query
	}
}

var (
	_ ControlCoverageQuery        = packageCoverageFixture{}
	_ CRAVulnerabilityQuery       = packageHandlingFixture{}
	_ SecurityUpdateEvidenceQuery = packageUpdateFixture{}
	_ ReleaseBundleQuery          = packageBundleReadFixture{}
	_ MissingEvidenceQuery        = packageMissingFixture{}
)
