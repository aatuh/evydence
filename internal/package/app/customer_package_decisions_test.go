package app

import (
	"reflect"
	"testing"
	"time"

	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestCustomerPackageDecisionSummariesPreservePublicFieldsAndOwnLists(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 34, 56, 123, time.FixedZone("fixture", 3600))
	values := []packagedomain.VulnerabilityDecisionSnapshot{
		{ID: "z", Vulnerability: "CVE-2", CreatedAt: now},
		{ID: "b", FindingID: "finding", ScanID: "scan", ReleaseID: "release", Vulnerability: "CVE-1", Component: "component", SBOMID: "sbom", SBOMComponentPURL: "purl", SBOMComponentName: "name", Status: "fixed", ImpactStatement: "impact", ActionStatement: "action", Justification: "reason", Source: "manual", EvidenceID: "evidence", VEXDocumentID: "vex", EvidenceIDs: []string{"evidence"}, SupportingRefs: []packagedomain.SupportingReference{{Type: "approval", ID: "approval", Digest: "sha256:approval"}}, ReviewedAt: &now, ReviewDueAt: &now, CreatedAt: now},
		{ID: "a", Vulnerability: "CVE-1", CreatedAt: now},
	}
	profile := packagedomain.RedactionProfile{AllowedTypes: []string{" vulnerability_decision "}}
	rows := CustomerPackageDecisionSummaries(values, profile)
	if len(rows) != 3 || rows[0]["id"] != "a" || rows[1]["id"] != "b" || rows[2]["id"] != "z" {
		t.Fatal("decision order changed", rows)
	}
	want := map[string]any{"id": "b", "finding_id": "finding", "scan_id": "scan", "release_id": "release", "vulnerability": "CVE-1", "component": "component", "sbom_id": "sbom", "sbom_component_purl": "purl", "sbom_component_name": "name", "status": "fixed", "impact_statement": "impact", "source": "manual", "created_at": "2026-10-04T11:34:56Z", "reviewed_at": "2026-10-04T11:34:56Z", "review_due_at": "2026-10-04T11:34:56Z", "action_statement": "action", "justification": "reason", "evidence_id": "evidence", "vex_document_id": "vex", "evidence_ids": []string{"evidence"}, "supporting_refs": []map[string]any{{"type": "approval", "id": "approval", "digest": "sha256:approval"}}}
	if !reflect.DeepEqual(rows[1], want) {
		t.Fatalf("public decision=%#v want=%#v", rows[1], want)
	}
	rows[1]["evidence_ids"].([]string)[0] = "changed"
	rows[1]["supporting_refs"].([]map[string]any)[0]["id"] = "changed"
	if values[1].EvidenceIDs[0] != "evidence" || values[1].SupportingRefs[0].ID != "approval" {
		t.Fatal("decision output aliases source")
	}
	for _, key := range []string{"reviewed_at", "review_due_at", "action_statement", "justification", "evidence_id", "vex_document_id", "evidence_ids", "supporting_refs"} {
		if _, exists := rows[0][key]; exists {
			t.Fatal("empty optional field included", key)
		}
	}
	profile.ExcludedFields = []string{" reviewed_at ", "review_due_at", "action_statement", "justification", "evidence_id", "vex_document_id", "evidence_ids", "supporting_refs"}
	for _, row := range CustomerPackageDecisionSummaries(values, profile) {
		for _, key := range profile.ExcludedFields {
			if _, exists := row[key]; exists {
				t.Fatal("excluded public field included", key)
			}
		}
		if _, exists := row["reviewed_at"]; exists {
			t.Fatal("trimmed exclusion ignored")
		}
	}
	if CustomerPackageDecisionSummaries(values, packagedomain.RedactionProfile{}) != nil {
		t.Fatal("disallowed decision type included")
	}
	if rows := CustomerPackageDecisionSummaries(nil, profile); rows == nil || len(rows) != 0 {
		t.Fatal("allowed empty decisions must be a nonnil collection", rows)
	}
}
