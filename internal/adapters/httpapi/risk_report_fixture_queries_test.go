package httpapi

import (
	"context"
	"maps"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Only historical HTTP tests use these full inventory reports. Runtime ports
// apply bounded PostgreSQL projections and their current-parent validators.
type riskReportFixture struct{ catalogFixtureCommands }

func (f riskReportFixture) Summary(ctx context.Context, a domain.Actor, release string) (riskdomain.ReleaseSecuritySummary, error) {
	v, err := f.commandLedger(ctx).ReleaseSecuritySummary(ctx, a, release)
	if err != nil {
		return riskdomain.ReleaseSecuritySummary{}, err
	}
	missing := make([]riskdomain.ReleaseSecurityMissingDecision, 0, len(v.MissingRequiredDecisions))
	for _, item := range v.MissingRequiredDecisions {
		missing = append(missing, riskdomain.ReleaseSecurityMissingDecision(item))
	}
	return riskdomain.ReleaseSecuritySummary{Product: riskdomain.ReleaseSecurityProductSummary(v.Product), Release: riskdomain.ReleaseSecurityReleaseSummary(v.Release), ArtifactCount: v.ArtifactCount, SBOMStatus: v.SBOMStatus, VulnerabilityScanStatus: v.VulnerabilityScanStatus, OpenFindingsBySeverity: maps.Clone(v.OpenFindingsBySeverity), DecisionsByStatus: maps.Clone(v.DecisionsByStatus), MissingRequiredDecisions: missing, ApprovalSummary: riskdomain.ReleaseSecurityApprovalSummary(v.ApprovalSummary), ExceptionSummary: riskdomain.ReleaseSecurityExceptionSummary(v.ExceptionSummary), ReadinessStatus: v.ReadinessStatus, PackageStatus: v.PackageStatus, Counts: maps.Clone(v.Counts), Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, GeneratedAt: v.GeneratedAt}, nil
}
func (f riskReportFixture) Report(ctx context.Context, a domain.Actor, release string) (packagedomain.VulnerabilityPostureReport, error) {
	v, err := f.commandLedger(ctx).VulnerabilityPostureReport(ctx, a, release)
	if err != nil {
		return packagedomain.VulnerabilityPostureReport{}, err
	}
	return packagedomain.VulnerabilityPostureReport{ReportType: v.ReportType, TemplateVersion: v.TemplateVersion, ReleaseID: v.ReleaseID, Summary: maps.Clone(v.Summary), OpenCritical: v.OpenCritical, Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), GeneratedAt: v.GeneratedAt}, nil
}
func (s *Server) bindRiskReportFixtureQueries(ledger *app.Ledger) {
	f := riskReportFixture{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.releaseSecuritySummaryQuery.(riskReportFixture); s.releaseSecuritySummaryQuery == nil || fixture {
		s.releaseSecuritySummaryQuery = f
	}
	if _, fixture := s.vulnerabilityPostureQuery.(riskReportFixture); s.vulnerabilityPostureQuery == nil || fixture {
		s.vulnerabilityPostureQuery = f
	}
}

var (
	_ ReleaseSecuritySummaryQuery = riskReportFixture{}
	_ VulnerabilityPostureQuery   = riskReportFixture{}
)
