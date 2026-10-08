package httpapi

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func assertPackageReportFixtureResponse(t *testing.T, path, want, got string) {
	t.Helper()
	var left, right any
	a, b := json.NewDecoder(strings.NewReader(want)), json.NewDecoder(strings.NewReader(got))
	a.UseNumber()
	b.UseNumber()
	if a.Decode(&left) != nil || b.Decode(&right) != nil || !reflect.DeepEqual(left, right) {
		t.Fatalf("report %s changed complete JSON response\nwant: %s\ngot: %s", path, want, got)
	}
}

// These independent public DTOs derive from known fixture inputs and returned
// write receipts, not the report query under test or obsolete aggregate caches.
func expectedPackageReportFixtureResponses(f packageReportFixtureScope) (domain.ControlCoverageReport, domain.CRAReadinessReport, domain.CRAVulnerabilityHandlingReport, domain.SecurityUpdateEvidenceReport) {
	controls := []domain.ControlCoverageItem{
		{ControlID: f.control.ID, Code: "REVIEW", Title: "Review", Status: "missing", Confidence: "unsupported", LinkedEvidence: []domain.ControlEvidence{}, Missing: []string{}, Explanation: "required control evidence is missing", Limitations: []string{"Human review required"}},
		{ControlID: f.sbomControl.ID, Code: "SBOM", Title: "sbom review", Status: "missing", Confidence: "unsupported", LinkedEvidence: []domain.ControlEvidence{}, Missing: []string{"sbom"}, Explanation: "required control evidence is missing", Limitations: []string{"Review required"}},
		{ControlID: f.vexControl.ID, Code: "VEX", Title: "vex review", Status: "waived", Confidence: "medium", Explanation: "approved unexpired exception waives this control for the selected scope", Limitations: []string{"Recorded exception"}},
	}
	coverage := domain.ControlCoverageReport{ReportType: "control_coverage", TemplateVersion: domain.ControlCoverageTemplateVersion, FrameworkID: f.framework.ID, ProductID: f.product.ID, ReleaseID: f.release.ID, Result: "failed", Controls: controls, MissingEvidence: []string{"sbom"}, AcceptedExceptions: []domain.Exception{f.exception}, Assumptions: []string{"Control coverage organizes technical evidence and is not a legal compliance conclusion."}, Limitations: []string{"Coverage is based only on evidence links, exceptions, and controls recorded in this Evydence instance."}, GeneratedAt: f.release.CreatedAt}
	cra := domain.CRAReadinessReport{ReportType: "cra_readiness", TemplateVersion: domain.CRAReadinessTemplateVersion, ProductID: f.product.ID, ReleaseID: f.release.ID, Result: "failed", Controls: controls, MissingEvidence: []string{"sbom"}, AcceptedExceptions: []domain.Exception{f.exception}, Assumptions: []string{"This report organizes technical evidence for CRA readiness review and is not a legal compliance conclusion."}, Limitations: []string{"Readiness is based only on evidence, mappings, exceptions, and release records in this Evydence instance.", "Evidence presence does not prove SBOM completeness, scanner authority, secure release status, or legal sufficiency."}, GeneratedAt: f.release.CreatedAt}
	d := f.decision
	evidenceIDs := []string{f.evidence.ID, f.scan.EvidenceID}
	sort.Strings(evidenceIDs)
	handling := domain.CRAVulnerabilityHandlingReport{
		ReportType: "cra_vulnerability_handling", TemplateVersion: "cra-vulnerability-handling.v1.0.0", ProductID: f.product.ID, ReleaseID: f.release.ID,
		Summary:            map[string]int{"findings_total": 1, "open_critical_total": 0, "decisions_total": 1, "approved_exceptions_total": 1, "evidence_total": 2},
		Decisions:          []domain.VulnerabilityDecisionCustomerSummary{{ID: d.ID, FindingID: f.scan.Findings[0].ID, ScanID: f.scan.ID, ReleaseID: f.release.ID, Vulnerability: "CVE-2026-0001", Component: "api", Status: "fixed", Justification: "Reviewed", ImpactStatement: "Patched", ActionStatement: "Ship patch", Source: "api", EvidenceIDs: []string{f.evidence.ID}, SupportingRefs: []domain.SubjectRef{{Type: "incident", ID: f.incident.ID}}, ReviewedAt: d.ReviewedAt, ReviewDueAt: d.ReviewDueAt, CreatedAt: d.CreatedAt}},
		AcceptedExceptions: []domain.Exception{f.exception}, EvidenceIDs: evidenceIDs,
		Assumptions: []string{"This report summarizes vulnerability handling records for CRA readiness review using evidence stored in this tenant."},
		Limitations: []string{"Report contents do not prove legal compliance, certification, complete vulnerability detection, scanner authority, or release security status."}, GeneratedAt: f.release.CreatedAt,
	}
	update := domain.SecurityUpdateEvidenceReport{
		ReportType: "security_update_evidence", TemplateVersion: "security-update-evidence.v1.0.0", ProductID: f.product.ID, ReleaseID: f.release.ID,
		Summary:        map[string]int{"fixed_decisions_total": 1, "incidents_total": 1, "remediation_tasks_total": 1, "linked_evidence_total": 2, "security_update_subjects": 3},
		FixedDecisions: handling.Decisions, Incidents: []domain.Incident{f.incident}, RemediationTasks: []domain.RemediationTask{f.task}, EvidenceIDs: evidenceIDs,
		Assumptions: []string{"This report summarizes recorded release evidence that may support security update review."},
		Limitations: []string{"Security update evidence is scoped to records in this Evydence tenant and does not prove legal sufficiency, customer notification completeness, or release security status."}, GeneratedAt: f.release.CreatedAt,
	}
	return coverage, cra, handling, update
}
