package httpapi

import (
	"context"
	"maps"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Historical report fixtures retain actual former owned read/grant rules and
// detach mutable metadata. Runtime readers remain bounded SQL projections.
type packageCoverageFixture struct{ catalogFixtureCommands }
type packageHandlingFixture struct{ catalogFixtureCommands }
type packageUpdateFixture struct{ catalogFixtureCommands }
type packageBundleReadFixture struct{ catalogFixtureCommands }
type packageMissingFixture struct{ catalogFixtureCommands }

func packageFixtureCoverageItems(values []domain.ControlCoverageItem) []packagedomain.ControlCoverageItem {
	items := make([]packagedomain.ControlCoverageItem, 0, len(values))
	for _, v := range values {
		links := make([]packagedomain.ControlEvidenceSnapshot, 0, len(v.LinkedEvidence))
		for _, link := range v.LinkedEvidence {
			links = append(links, packagedomain.ControlEvidenceSnapshot(link))
		}
		items = append(items, packagedomain.ControlCoverageItem{ControlID: v.ControlID, Code: v.Code, Title: v.Title, Status: v.Status, Confidence: v.Confidence, LinkedEvidence: links, Missing: slices.Clone(v.Missing), Explanation: v.Explanation, Limitations: slices.Clone(v.Limitations)})
	}
	return items
}
func packageFixtureExceptions(values []domain.Exception) []packagedomain.AcceptedExceptionSnapshot {
	items := make([]packagedomain.AcceptedExceptionSnapshot, 0, len(values))
	for _, v := range values {
		v.ApprovedAt = copyDecisionSummaryTime(v.ApprovedAt)
		items = append(items, packagedomain.AcceptedExceptionSnapshot(v))
	}
	return items
}
func packageFixtureDecisions(values []domain.VulnerabilityDecisionCustomerSummary) []packagedomain.VulnerabilityDecisionSnapshot {
	items := make([]packagedomain.VulnerabilityDecisionSnapshot, 0, len(values))
	for _, v := range values {
		refs := make([]packagedomain.SupportingReference, 0, len(v.SupportingRefs))
		for _, ref := range v.SupportingRefs {
			refs = append(refs, packagedomain.SupportingReference(ref))
		}
		items = append(items, packagedomain.VulnerabilityDecisionSnapshot{ID: v.ID, FindingID: v.FindingID, ScanID: v.ScanID, ReleaseID: v.ReleaseID, Vulnerability: v.Vulnerability, Component: v.Component, SBOMID: v.SBOMID, SBOMComponentPURL: v.SBOMComponentPURL, SBOMComponentName: v.SBOMComponentName, Status: v.Status, Justification: v.Justification, ImpactStatement: v.ImpactStatement, ActionStatement: v.ActionStatement, Source: v.Source, EvidenceID: v.EvidenceID, EvidenceIDs: slices.Clone(v.EvidenceIDs), SupportingRefs: refs, VEXDocumentID: v.VEXDocumentID, ReviewedAt: copyDecisionSummaryTime(v.ReviewedAt), ReviewDueAt: copyDecisionSummaryTime(v.ReviewDueAt), CreatedAt: v.CreatedAt})
	}
	return items
}
func (f packageCoverageFixture) Coverage(ctx context.Context, a domain.Actor, filter packagequery.ControlCoverageFilter) (packagedomain.ControlCoverageReport, error) {
	v, err := f.commandLedger(ctx).ControlCoverageReport(ctx, a, app.ControlCoverageReportInput(filter))
	if err != nil {
		return packagedomain.ControlCoverageReport{}, err
	}
	return packagedomain.ControlCoverageReport{ReportType: v.ReportType, TemplateVersion: v.TemplateVersion, FrameworkID: v.FrameworkID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Result: v.Result, Controls: packageFixtureCoverageItems(v.Controls), MissingEvidence: slices.Clone(v.MissingEvidence), AcceptedExceptions: packageFixtureExceptions(v.AcceptedExceptions), Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), GeneratedAt: v.GeneratedAt}, nil
}
func (f packageCoverageFixture) CRAReadiness(ctx context.Context, a domain.Actor, product, release string) (packagedomain.CRAReadinessReport, error) {
	v, err := f.commandLedger(ctx).CRAReadinessReport(ctx, a, app.CRAReadinessReportInput{ProductID: product, ReleaseID: release})
	if err != nil {
		return packagedomain.CRAReadinessReport{}, err
	}
	return packagedomain.CRAReadinessReport{ReportType: v.ReportType, TemplateVersion: v.TemplateVersion, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Result: v.Result, Controls: packageFixtureCoverageItems(v.Controls), MissingEvidence: slices.Clone(v.MissingEvidence), AcceptedExceptions: packageFixtureExceptions(v.AcceptedExceptions), Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), GeneratedAt: v.GeneratedAt}, nil
}
func (f packageHandlingFixture) Report(ctx context.Context, a domain.Actor, product, release string) (packagedomain.CRAVulnerabilityHandlingReport, error) {
	v, err := f.commandLedger(ctx).CRAVulnerabilityHandlingReport(ctx, a, product, release)
	if err != nil {
		return packagedomain.CRAVulnerabilityHandlingReport{}, err
	}
	return packagedomain.CRAVulnerabilityHandlingReport{ReportType: v.ReportType, TemplateVersion: v.TemplateVersion, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Summary: maps.Clone(v.Summary), Decisions: packageFixtureDecisions(v.Decisions), AcceptedExceptions: packageFixtureExceptions(v.AcceptedExceptions), EvidenceIDs: slices.Clone(v.EvidenceIDs), Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), GeneratedAt: v.GeneratedAt}, nil
}
func (f packageUpdateFixture) Report(ctx context.Context, a domain.Actor, product, release string) (packagedomain.SecurityUpdateEvidenceReport, error) {
	v, err := f.commandLedger(ctx).SecurityUpdateEvidenceReport(ctx, a, product, release)
	if err != nil {
		return packagedomain.SecurityUpdateEvidenceReport{}, err
	}
	incidents := make([]packagedomain.IncidentSnapshot, 0, len(v.Incidents))
	for _, incident := range v.Incidents {
		incident.ClosedAt = copyDecisionSummaryTime(incident.ClosedAt)
		incidents = append(incidents, packagedomain.IncidentSnapshot(incident))
	}
	tasks := make([]packagedomain.RemediationTaskSnapshot, 0, len(v.RemediationTasks))
	for _, task := range v.RemediationTasks {
		task.DueAt = copyDecisionSummaryTime(task.DueAt)
		tasks = append(tasks, packagedomain.RemediationTaskSnapshot(task))
	}
	return packagedomain.SecurityUpdateEvidenceReport{ReportType: v.ReportType, TemplateVersion: v.TemplateVersion, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Summary: maps.Clone(v.Summary), FixedDecisions: packageFixtureDecisions(v.FixedDecisions), Incidents: incidents, RemediationTasks: tasks, EvidenceIDs: slices.Clone(v.EvidenceIDs), Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), GeneratedAt: v.GeneratedAt}, nil
}
func (f packageBundleReadFixture) GetReleaseBundle(ctx context.Context, a domain.Actor, id string) (packagedomain.ReleaseBundle, error) {
	v, err := f.commandLedger(ctx).GetReleaseBundle(ctx, a, id)
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	return domain.ReleaseBundleToContextModel(v)
}

// The retired missing-evidence GET called a write-producing evaluation. Use
// real fixture authority plus a read-only readiness report instead, then the
// same pure Package renderer used by the supported PostgreSQL query.
func (f packageMissingFixture) Preview(ctx context.Context, a domain.Actor, id string) (riskdomain.PolicyEvaluation, error) {
	if err := riskCommandFixture(f).AuthorizeEvaluateRelease(ctx, a, id); err != nil {
		return riskdomain.PolicyEvaluation{}, err
	}
	reader := domain.Actor{TenantID: a.TenantID, KeyID: "fixture-owned-readiness-reader", Scopes: []string{"verify:read"}}
	v, err := f.commandLedger(ctx).ReleaseReadinessReport(ctx, reader, id)
	if err != nil {
		return riskdomain.PolicyEvaluation{}, err
	}
	return policyEvaluationFixtureModel(domain.PolicyEvaluation{TenantID: a.TenantID, ReleaseID: id, Result: v.Result, PolicySet: v.PolicySet, Checks: v.Checks, CreatedAt: v.GeneratedAt}), nil
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
	if _, fixture := s.controlCoverageQuery.(packageCoverageFixture); s.controlCoverageQuery == nil || fixture {
		s.controlCoverageQuery = packageCoverageFixture{f}
	}
	if _, fixture := s.craVulnerabilityQuery.(packageHandlingFixture); s.craVulnerabilityQuery == nil || fixture {
		s.craVulnerabilityQuery = packageHandlingFixture{f}
	}
	if _, fixture := s.securityUpdateEvidenceQuery.(packageUpdateFixture); s.securityUpdateEvidenceQuery == nil || fixture {
		s.securityUpdateEvidenceQuery = packageUpdateFixture{f}
	}
	if _, fixture := s.releaseBundleQuery.(packageBundleReadFixture); s.releaseBundleQuery == nil || fixture {
		s.releaseBundleQuery = packageBundleReadFixture{f}
	}
	if _, fixture := s.missingEvidenceQuery.(packageMissingFixture); s.missingEvidenceQuery == nil || fixture {
		s.missingEvidenceQuery = packageMissingFixture{f}
	}
}

var (
	_ ControlCoverageQuery        = packageCoverageFixture{}
	_ CRAVulnerabilityQuery       = packageHandlingFixture{}
	_ SecurityUpdateEvidenceQuery = packageUpdateFixture{}
	_ ReleaseBundleQuery          = packageBundleReadFixture{}
	_ MissingEvidenceQuery        = packageMissingFixture{}
)
