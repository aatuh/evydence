package app

import (
	"errors"
	"testing"
	"time"

	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestMapVEXDecisionsSupersedesActiveDecisionAndIsIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 6, 9, 0, 0, 0, time.UTC)
	oldStatus, _ := riskdomain.ParseDecisionStatus(riskdomain.DecisionStatusAffectedValue)
	input := VEXMappingInput{
		TenantID: "ten_1", ReleaseID: "rel_1", VEXDocumentID: "vex_1", EvidenceID: "ev_1",
		ActorID: "key_1", Source: "vex", CreatedAt: now,
		Statements:        []VEXStatement{{Index: 1, Vulnerability: "CVE-1", Products: []string{"pkg:a@1"}, Status: "fixed", Justification: "patched"}},
		Findings:          []VEXFinding{{ID: "finding_1", ScanID: "scan_1", TenantID: "ten_1", ReleaseID: "rel_1", Vulnerability: "CVE-1", Component: "pkg:a@1", SBOMID: "sbom_1", SBOMComponentPURL: "pkg:a@1"}},
		ExistingDecisions: []riskdomain.VulnerabilityDecision{{ID: "vd_old", TenantID: "ten_1", ReleaseID: "rel_1", FindingID: "finding_1", Status: oldStatus}},
	}
	result, err := MapVEXDecisions(input, VEXDecisionIDFunc(func(_, _, _ string) string { return "vd_new" }))
	if err != nil {
		t.Fatalf("map vex: %v", err)
	}
	if len(result.Created) != 1 || result.Created[0].Supersedes != "vd_old" || result.Created[0].ReviewedAt == nil || len(result.Superseded) != 1 || result.Superseded[0].SupersededBy != "vd_new" {
		t.Fatalf("mapping = %#v", result)
	}
	if result.Created[0].SBOMID != "sbom_1" || result.Created[0].EvidenceID != "ev_1" || result.Created[0].Status.String() != "fixed" {
		t.Fatalf("decision = %#v", result.Created[0])
	}

	input.ExistingDecisions = append(input.ExistingDecisions, result.Created[0])
	replay, err := MapVEXDecisions(input, VEXDecisionIDFunc(func(_, _, _ string) string { return "vd_new" }))
	if err != nil || len(replay.Created) != 0 || len(replay.Superseded) != 0 {
		t.Fatalf("idempotent replay = %#v, %v", replay, err)
	}
}

func TestMapVEXDecisionsRejectsAmbiguousAndReportsMissingFindings(t *testing.T) {
	input := VEXMappingInput{
		TenantID: "ten_1", ReleaseID: "rel_1", VEXDocumentID: "vex_1", EvidenceID: "ev_1", ActorID: "key_1", Source: "vex", CreatedAt: time.Now(),
		Statements: []VEXStatement{{Index: 2, Vulnerability: "CVE-1", Status: "affected"}, {Index: 3, Vulnerability: "CVE-2", Status: "fixed"}},
		Findings: []VEXFinding{
			{ID: "finding_1", ScanID: "scan_1", TenantID: "ten_1", ReleaseID: "rel_1", Vulnerability: "CVE-1", Component: "pkg:a@1"},
			{ID: "finding_2", ScanID: "scan_2", TenantID: "ten_1", ReleaseID: "rel_1", Vulnerability: "CVE-1", Component: "pkg:b@1"},
		},
	}
	result, err := MapVEXDecisions(input, VEXDecisionIDFunc(func(_, findingID, _ string) string { return "vd_" + findingID }))
	if err != nil {
		t.Fatalf("map vex: %v", err)
	}
	if len(result.Created) != 0 || len(result.Failures) != 2 || result.Failures[0].Code != "ambiguous_finding" || result.Failures[1].Code != "finding_not_found" {
		t.Fatalf("failures = %#v", result)
	}
}

func TestMapVEXDecisionsRejectsForeignFinding(t *testing.T) {
	input := VEXMappingInput{
		TenantID: "ten_1", ReleaseID: "rel_1", VEXDocumentID: "vex_1", EvidenceID: "ev_1", ActorID: "key_1", Source: "vex", CreatedAt: time.Now(),
		Statements: []VEXStatement{{Index: 1, Vulnerability: "CVE-1", Status: "fixed"}},
		Findings:   []VEXFinding{{ID: "finding_1", ScanID: "scan_1", TenantID: "ten_2", ReleaseID: "rel_1", Vulnerability: "CVE-1"}},
	}
	if _, err := MapVEXDecisions(input, VEXDecisionIDFunc(func(_, _, _ string) string { return "vd_1" })); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign finding error = %v", err)
	}
}
