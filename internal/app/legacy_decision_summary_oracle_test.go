package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Historical package-local characterization only. Production and HTTP queries
// use the focused, current-repository summary path rather than these facades.
func (l *Ledger) VulnerabilityDecisionSummaryReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.VulnerabilityDecisionSummaryReport, error) {
	value, err := l.riskCommands.VulnerabilityDecisionSummaryReport(ctx, actor, releaseID)
	if err != nil {
		return domain.VulnerabilityDecisionSummaryReport{}, fromRiskContextError(err)
	}
	decisions := make([]domain.VulnerabilityDecisionCustomerSummary, 0, len(value.Decisions))
	for _, decision := range value.Decisions {
		decisions = append(decisions, riskDecisionSummaryToLegacy(decision))
	}
	return domain.VulnerabilityDecisionSummaryReport{
		ReportType: value.ReportType, TemplateVersion: value.TemplateVersion, ProductID: value.ProductID,
		ReleaseID: value.ReleaseID, Decisions: decisions, Assumptions: append([]string(nil), value.Assumptions...),
		Limitations: append([]string(nil), value.Limitations...), GeneratedAt: value.GeneratedAt,
	}, nil
}

func riskDecisionSummaryToLegacy(value riskdomain.VulnerabilityDecisionCustomerSummary) domain.VulnerabilityDecisionCustomerSummary {
	return domain.VulnerabilityDecisionCustomerSummary{
		ID: value.ID, FindingID: value.FindingID, ScanID: value.ScanID, ReleaseID: value.ReleaseID,
		Vulnerability: value.Vulnerability, Component: value.Component, SBOMID: value.SBOMID,
		SBOMComponentPURL: value.SBOMComponentPURL, SBOMComponentName: value.SBOMComponentName,
		Status: value.Status, Justification: value.Justification, ImpactStatement: value.ImpactStatement,
		ActionStatement: value.ActionStatement, Source: value.Source, EvidenceID: value.EvidenceID,
		EvidenceIDs: append([]string(nil), value.EvidenceIDs...), SupportingRefs: riskSupportingRefsToLegacy(value.SupportingRefs),
		VEXDocumentID: value.VEXDocumentID, ReviewedAt: cloneTimePtr(value.ReviewedAt), ReviewDueAt: cloneTimePtr(value.ReviewDueAt),
		CreatedAt: value.CreatedAt,
	}
}

func riskSupportingRefsToLegacy(values []riskdomain.SupportingReference) []domain.SubjectRef {
	result := make([]domain.SubjectRef, 0, len(values))
	for _, value := range values {
		result = append(result, domain.SubjectRef{Type: value.Type, ID: value.ID, Digest: value.Digest})
	}
	return result
}

func customerDecisionSummary(decision domain.VulnerabilityDecision) domain.VulnerabilityDecisionCustomerSummary {
	return domain.VulnerabilityDecisionCustomerSummary{
		ID:                decision.ID,
		FindingID:         decision.FindingID,
		ScanID:            decision.ScanID,
		ReleaseID:         decision.ReleaseID,
		Vulnerability:     decision.Vulnerability,
		Component:         decision.Component,
		SBOMID:            decision.SBOMID,
		SBOMComponentPURL: decision.SBOMComponentPURL,
		SBOMComponentName: decision.SBOMComponentName,
		Status:            decision.Status,
		Justification:     decision.Justification,
		ImpactStatement:   decision.ImpactStatement,
		ActionStatement:   decision.ActionStatement,
		Source:            decision.Source,
		EvidenceID:        decision.EvidenceID,
		EvidenceIDs:       append([]string(nil), decision.EvidenceIDs...),
		SupportingRefs:    cloneSubjectRefs(decision.SupportingRefs),
		VEXDocumentID:     decision.VEXDocumentID,
		ReviewedAt:        cloneTimePtr(decision.ReviewedAt),
		ReviewDueAt:       cloneTimePtr(decision.ReviewDueAt),
		CreatedAt:         decision.CreatedAt,
	}
}
