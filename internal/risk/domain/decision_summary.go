package domain

import "time"

// CustomerDecisionSummary is the only decision projection permitted in a
// customer-facing vulnerability report. Internal triage notes are omitted.
func CustomerDecisionSummary(value VulnerabilityDecision) VulnerabilityDecisionCustomerSummary {
	var reviewedAt, reviewDueAt *time.Time
	if value.ReviewedAt != nil {
		at := value.ReviewedAt.UTC()
		reviewedAt = &at
	}
	if value.ReviewDueAt != nil {
		at := value.ReviewDueAt.UTC()
		reviewDueAt = &at
	}
	return VulnerabilityDecisionCustomerSummary{
		ID: value.ID, FindingID: value.FindingID, ScanID: value.ScanID, ReleaseID: value.ReleaseID,
		Vulnerability: value.Vulnerability, Component: value.Component, SBOMID: value.SBOMID,
		SBOMComponentPURL: value.SBOMComponentPURL, SBOMComponentName: value.SBOMComponentName,
		Status: value.Status.String(), Justification: value.Justification, ImpactStatement: value.ImpactStatement,
		ActionStatement: value.ActionStatement, Source: value.Source, EvidenceID: value.EvidenceID,
		EvidenceIDs: append([]string(nil), value.EvidenceIDs...), SupportingRefs: append([]SupportingReference(nil), value.SupportingRefs...),
		VEXDocumentID: value.VEXDocumentID, ReviewedAt: reviewedAt, ReviewDueAt: reviewDueAt, CreatedAt: value.CreatedAt,
	}
}

// NewVulnerabilityDecisionSummaryReport preserves the versioned report
// language across the compatibility and focused query paths.
func NewVulnerabilityDecisionSummaryReport(productID, releaseID string, decisions []VulnerabilityDecisionCustomerSummary, generatedAt time.Time) VulnerabilityDecisionSummaryReport {
	return VulnerabilityDecisionSummaryReport{
		ReportType: "vulnerability_decision_summary", TemplateVersion: "vulnerability-decision-summary.v1.0.0",
		ProductID: productID, ReleaseID: releaseID, Decisions: decisions,
		Assumptions: []string{
			"Only active vulnerability decisions marked customer_visible are included.",
			"Evidence identifiers point to records in this Evydence instance; raw evidence payload bytes are not included.",
			"reviewed_at records when the decision was reviewed; missing review_due_at means no scheduled follow-up review was recorded.",
		},
		Limitations: []string{
			"This summary supports compliance-readiness review; it is not certification, legal advice, complete SBOM proof, or authoritative vulnerability coverage.",
			"Decision accuracy depends on tenant-supplied evidence, scanner inputs, and review quality.",
			"Review dates are tenant-supplied metadata and do not prove that the underlying vulnerability analysis is still correct.",
		},
		GeneratedAt: generatedAt.UTC(),
	}
}
