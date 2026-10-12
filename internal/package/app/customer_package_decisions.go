package app

import (
	"sort"
	"strings"
	"time"

	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// CustomerPackageDecisionSummaries formats already scope-checked, active,
// customer-visible decisions. The projection deliberately has no internal
// notes or reviewer identity. Both runtime profiles use these public fields.
func CustomerPackageDecisionSummaries(values []packagedomain.VulnerabilityDecisionSnapshot, profile packagedomain.RedactionProfile) []map[string]any {
	if !CustomerPackageIncludesType(profile, "vulnerability_decision") {
		return nil
	}
	excluded := make(map[string]bool, len(profile.ExcludedFields))
	for _, field := range profile.ExcludedFields {
		excluded[strings.TrimSpace(field)] = true
	}
	rows := make([]map[string]any, 0, len(values))
	for _, v := range values {
		row := map[string]any{
			"id": v.ID, "finding_id": v.FindingID, "scan_id": v.ScanID, "release_id": v.ReleaseID,
			"vulnerability": v.Vulnerability, "component": v.Component, "sbom_id": v.SBOMID,
			"sbom_component_purl": v.SBOMComponentPURL, "sbom_component_name": v.SBOMComponentName,
			"status": v.Status, "impact_statement": v.ImpactStatement, "source": v.Source,
			"created_at": v.CreatedAt.UTC().Format(time.RFC3339),
		}
		for key, value := range map[string]string{"action_statement": v.ActionStatement, "justification": v.Justification, "evidence_id": v.EvidenceID, "vex_document_id": v.VEXDocumentID} {
			if value != "" && !excluded[key] {
				row[key] = value
			}
		}
		for key, value := range map[string]*time.Time{"reviewed_at": v.ReviewedAt, "review_due_at": v.ReviewDueAt} {
			if value != nil && !excluded[key] {
				row[key] = value.UTC().Format(time.RFC3339)
			}
		}
		if len(v.EvidenceIDs) > 0 && !excluded["evidence_ids"] {
			row["evidence_ids"] = append([]string(nil), v.EvidenceIDs...)
		}
		if len(v.SupportingRefs) > 0 && !excluded["supporting_refs"] {
			refs := make([]map[string]any, 0, len(v.SupportingRefs))
			for _, ref := range v.SupportingRefs {
				public := map[string]any{"type": ref.Type}
				if ref.ID != "" {
					public["id"] = ref.ID
				}
				if ref.Digest != "" {
					public["digest"] = ref.Digest
				}
				refs = append(refs, public)
			}
			row["supporting_refs"] = refs
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i]["vulnerability"].(string)+"\x00"+rows[i]["id"].(string) < rows[j]["vulnerability"].(string)+"\x00"+rows[j]["id"].(string)
	})
	return rows
}
