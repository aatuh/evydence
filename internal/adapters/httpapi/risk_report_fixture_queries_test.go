package httpapi

import (
	"context"
	"maps"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Only historical HTTP tests use these full inventory reports. Runtime ports
// apply bounded PostgreSQL projections and their current-parent validators.
type riskReportFixture struct{ catalogFixtureCommands }

func (f riskReportFixture) Report(ctx context.Context, a domain.Actor, release string) (packagedomain.VulnerabilityPostureReport, error) {
	v, err := f.commandLedger(ctx).VulnerabilityPostureReport(ctx, a, release)
	if err != nil {
		return packagedomain.VulnerabilityPostureReport{}, err
	}
	return packagedomain.VulnerabilityPostureReport{ReportType: v.ReportType, TemplateVersion: v.TemplateVersion, ReleaseID: v.ReleaseID, Summary: maps.Clone(v.Summary), OpenCritical: v.OpenCritical, Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), GeneratedAt: v.GeneratedAt}, nil
}
func (s *Server) bindRiskReportFixtureQueries(ledger *app.Ledger) {
	f := riskReportFixture{catalogFixtureCommands{ledger: ledger}}
	if query, fixture := s.releaseSecuritySummaryQuery.(releaseSummaryNativeFixture); s.releaseSecuritySummaryQuery == nil || fixture {
		query.catalogFixtureCommands = f.catalogFixtureCommands
		s.releaseSecuritySummaryQuery = query
	}
	if _, fixture := s.vulnerabilityPostureQuery.(riskReportFixture); s.vulnerabilityPostureQuery == nil || fixture {
		s.vulnerabilityPostureQuery = f
	}
}

var (
	_ VulnerabilityPostureQuery = riskReportFixture{}
)
