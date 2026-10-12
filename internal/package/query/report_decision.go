package query

import (
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// reportDecisionSnapshot is the shared customer-facing projection for
// vulnerability reports. Callers validate release ownership and active state.
func reportDecisionSnapshot(decision riskdomain.VulnerabilityDecision) packagedomain.VulnerabilityDecisionSnapshot {
	customer := riskdomain.CustomerDecisionSummary(decision)
	refs := make([]packagedomain.SupportingReference, 0, len(customer.SupportingRefs))
	for _, ref := range customer.SupportingRefs {
		refs = append(refs, packagedomain.SupportingReference{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
	}
	return packagedomain.VulnerabilityDecisionSnapshot{
		ID: customer.ID, FindingID: customer.FindingID, ScanID: customer.ScanID, ReleaseID: customer.ReleaseID,
		Vulnerability: customer.Vulnerability, Component: customer.Component, SBOMID: customer.SBOMID,
		SBOMComponentPURL: customer.SBOMComponentPURL, SBOMComponentName: customer.SBOMComponentName,
		Status: customer.Status, Justification: customer.Justification, ImpactStatement: customer.ImpactStatement,
		ActionStatement: customer.ActionStatement, Source: customer.Source, EvidenceID: customer.EvidenceID,
		EvidenceIDs: customer.EvidenceIDs, SupportingRefs: refs, VEXDocumentID: customer.VEXDocumentID,
		ReviewedAt: customer.ReviewedAt, ReviewDueAt: customer.ReviewDueAt, CreatedAt: customer.CreatedAt,
	}
}
