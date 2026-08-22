package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestOpenVEXStatusMappingFixtures(t *testing.T) {
	tests := []struct {
		name          string
		status        string
		justification string
	}{
		{name: "not affected", status: decisionStatusNotAffected, justification: "component_not_present"},
		{name: "affected", status: decisionStatusAffected, justification: "vulnerable_code_present"},
		{name: "fixed", status: decisionStatusFixed, justification: "fixed_in_release"},
		{name: "under investigation", status: decisionStatusUnderInvestigation, justification: "triage_in_progress"},
	}

	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
			ctx := context.Background()
			actor, release, artifact := setupReleaseRiskFixture(t, ledger)
			vulnerability := fmt.Sprintf("CVE-2026-%04d", index+100)
			component := fmt.Sprintf("pkg:apk/component-%d@1.0.0", index)
			uploadVEXMappingScan(t, ctx, ledger, actor, release.ID, vulnerability, component)

			vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
				openVEXStatementFixture(vulnerability, []map[string]any{{"@id": component}}, tt.status, tt.justification),
			}))
			if err != nil {
				t.Fatalf("upload vex: %v", err)
			}

			active := true
			decisions, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{
				ReleaseID:     release.ID,
				Vulnerability: vulnerability,
				Active:        &active,
			})
			if err != nil {
				t.Fatalf("list decisions: %v", err)
			}
			if len(decisions) != 1 {
				t.Fatalf("decisions = %#v, want one", decisions)
			}
			decision := decisions[0]
			if decision.Status != tt.status || decision.Source != "vex" || decision.VEXDocumentID != vex.ID || decision.Justification != tt.justification || !decision.CustomerVisible {
				t.Fatalf("decision = %#v", decision)
			}
			report, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
			if err != nil {
				t.Fatalf("import report: %v", err)
			}
			if report.StatementCount != 1 || report.DecisionsCreated != 1 || len(report.MappingFailures) != 0 {
				t.Fatalf("import report = %#v", report)
			}
		})
	}
}

func TestOpenVEXMappingMultipleProductsAndReleaseScope(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, releaseA, artifact := setupReleaseRiskFixture(t, ledger)
	releaseB, err := ledger.CreateRelease(ctx, actor, releaseA.ProductID, "2.0.0")
	if err != nil {
		t.Fatalf("release B: %v", err)
	}
	vulnerability := "CVE-2026-0200"
	componentA := "pkg:oci/payments-api@sha256:a"
	componentB := "pkg:oci/payments-api@sha256:b"
	uploadVEXMappingScan(t, ctx, ledger, actor, releaseA.ID, vulnerability, componentA)
	uploadVEXMappingScan(t, ctx, ledger, actor, releaseB.ID, vulnerability, componentB)

	vex, err := ledger.UploadVEX(ctx, actor, releaseA.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture(vulnerability, []map[string]any{
			{"@id": "pkg:oci/aggregate", "subcomponents": []map[string]any{{"@id": componentA}}},
			{"@id": componentB},
		}, decisionStatusFixed, "fixed_in_release"),
	}))
	if err != nil {
		t.Fatalf("upload vex: %v", err)
	}

	active := true
	releaseADecisions, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: releaseA.ID, Vulnerability: vulnerability, Active: &active})
	if err != nil {
		t.Fatalf("list release A decisions: %v", err)
	}
	releaseBDecisions, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: releaseB.ID, Vulnerability: vulnerability, Active: &active})
	if err != nil {
		t.Fatalf("list release B decisions: %v", err)
	}
	if len(releaseADecisions) != 1 || releaseADecisions[0].Component != componentA {
		t.Fatalf("release A decisions = %#v", releaseADecisions)
	}
	if len(releaseBDecisions) != 0 {
		t.Fatalf("VEX uploaded for release A created release B decisions: %#v", releaseBDecisions)
	}
	report, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("import report: %v", err)
	}
	if report.DecisionsCreated != 1 || len(report.MappingFailures) != 0 {
		t.Fatalf("import report = %#v", report)
	}
}

func TestOpenVEXDuplicateStatementIsIdempotentWithinImport(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	vulnerability := "CVE-2026-0300"
	component := "pkg:apk/openssl@3.1.0"
	uploadVEXMappingScan(t, ctx, ledger, actor, release.ID, vulnerability, component)
	statement := openVEXStatementFixture(vulnerability, []map[string]any{{"@id": component}}, decisionStatusFixed, "fixed_in_release")

	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{statement, statement}))
	if err != nil {
		t.Fatalf("upload vex: %v", err)
	}
	active := true
	decisions, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: release.ID, Vulnerability: vulnerability, Active: &active})
	if err != nil {
		t.Fatalf("list active decisions: %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("active decisions = %#v, want one", decisions)
	}
	inactive := false
	superseded, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: release.ID, Vulnerability: vulnerability, Active: &inactive})
	if err != nil {
		t.Fatalf("list superseded decisions: %v", err)
	}
	if len(superseded) != 0 {
		t.Fatalf("duplicate statement should not create superseded duplicate versions: %#v", superseded)
	}
	report, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("import report: %v", err)
	}
	if report.DecisionsCreated != 1 || report.DecisionsSuperseded != 0 || !stringSliceContains(report.Warnings, "Duplicate VEX statements") {
		t.Fatalf("import report = %#v", report)
	}
}

func TestOpenVEXAmbiguousFindingIsReportedWithoutDecision(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	const vulnerability = "CVE-2026-0350"
	const component = "pkg:apk/openssl@3.1.0"
	uploadVEXMappingScan(t, ctx, ledger, actor, release.ID, vulnerability, component)
	uploadVEXMappingScan(t, ctx, ledger, actor, release.ID, vulnerability, component)

	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture(vulnerability, []map[string]any{{"@id": component}}, decisionStatusFixed, "fixed_in_release"),
	}))
	if err != nil {
		t.Fatalf("upload vex: %v", err)
	}
	report, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil || len(report.MappingFailures) != 1 || report.MappingFailures[0].Code != "ambiguous_finding" || report.DecisionsCreated != 0 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	active := true
	decisions, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: release.ID, Vulnerability: vulnerability, Active: &active})
	if err != nil || len(decisions) != 0 {
		t.Fatalf("decisions=%#v err=%v", decisions, err)
	}
}

func TestUnambiguousVEXMatchesPolicy(t *testing.T) {
	match := func(component string) matchedFinding {
		return matchedFinding{finding: domain.VulnerabilityFinding{Component: component}}
	}
	if matches, ambiguous := unambiguousVEXMatches(nil, nil); ambiguous || len(matches) != 0 {
		t.Fatalf("empty matches=%#v ambiguous=%v", matches, ambiguous)
	}
	if _, ambiguous := unambiguousVEXMatches([]matchedFinding{match("pkg:a"), match("pkg:b")}, nil); !ambiguous {
		t.Fatal("unscoped multi-match must be ambiguous")
	}
	if _, ambiguous := unambiguousVEXMatches([]matchedFinding{match("pkg:a"), match("pkg:b")}, map[string]struct{}{"pkg:a": {}}); !ambiguous {
		t.Fatal("more matches than product refs must be ambiguous")
	}
	if _, ambiguous := unambiguousVEXMatches([]matchedFinding{match(""), match("pkg:a")}, map[string]struct{}{"pkg:a": {}, "pkg:b": {}}); !ambiguous {
		t.Fatal("empty component must be ambiguous")
	}
	if _, ambiguous := unambiguousVEXMatches([]matchedFinding{match("pkg:c"), match("pkg:a")}, map[string]struct{}{"pkg:a": {}, "pkg:b": {}}); !ambiguous {
		t.Fatal("unlisted component must be ambiguous")
	}
	if _, ambiguous := unambiguousVEXMatches([]matchedFinding{match("pkg:a"), match("pkg:a")}, map[string]struct{}{"pkg:a": {}, "pkg:b": {}}); !ambiguous {
		t.Fatal("duplicate component must be ambiguous")
	}
	matches, ambiguous := unambiguousVEXMatches([]matchedFinding{match("pkg:a"), match("pkg:b")}, map[string]struct{}{"pkg:a": {}, "pkg:b": {}})
	if ambiguous || len(matches) != 2 {
		t.Fatalf("explicit unique matches=%#v ambiguous=%v", matches, ambiguous)
	}
}

func TestOpenVEXMappingSupersedesExistingDecisionFixture(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	vulnerability := "CVE-2026-0400"
	component := "pkg:apk/openssl@3.1.0"
	scan := uploadVEXMappingScan(t, ctx, ledger, actor, release.ID, vulnerability, component)
	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusUnderInvestigation,
		Justification:   "manual_triage",
		ImpactStatement: "Manual triage is in progress.",
	}); err != nil {
		t.Fatalf("manual decision: %v", err)
	}

	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture(vulnerability, []map[string]any{{"@id": component}}, decisionStatusFixed, "fixed_in_release"),
	}))
	if err != nil {
		t.Fatalf("upload vex: %v", err)
	}
	active := true
	activeDecisions, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: release.ID, Vulnerability: vulnerability, Active: &active})
	if err != nil {
		t.Fatalf("list active decisions: %v", err)
	}
	inactive := false
	superseded, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: release.ID, Vulnerability: vulnerability, Active: &inactive})
	if err != nil {
		t.Fatalf("list superseded decisions: %v", err)
	}
	if len(activeDecisions) != 1 || activeDecisions[0].Status != decisionStatusFixed || len(superseded) != 1 || superseded[0].Status != decisionStatusUnderInvestigation {
		t.Fatalf("active=%#v superseded=%#v", activeDecisions, superseded)
	}
	report, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("import report: %v", err)
	}
	if report.DecisionsCreated != 1 || report.DecisionsSuperseded != 1 {
		t.Fatalf("import report = %#v", report)
	}
}

func TestOpenVEXValidationFixturesReturnUsefulSafeErrors(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	tests := []struct {
		name       string
		payload    []byte
		wantDetail string
		notContain string
	}{
		{
			name: "unknown status",
			payload: openVEXFixture(t, []map[string]any{
				openVEXStatementFixture("CVE-2026-0500", []map[string]any{{"@id": "pkg:apk/openssl@3.1.0"}}, "secret-token-status", "triage"),
			}),
			wantDetail: "openvex JSON is malformed or violates required OpenVEX fields",
			notContain: "secret-token-status",
		},
		{
			name: "component identity missing",
			payload: openVEXFixture(t, []map[string]any{
				openVEXStatementFixture("CVE-2026-0501", []map[string]any{{"@id": ""}}, decisionStatusFixed, "fixed"),
			}),
			wantDetail: "openvex JSON is malformed or violates required OpenVEX fields",
		},
		{
			name:       "malformed document",
			payload:    []byte(`{"author":"security@example.test"`),
			wantDetail: "openvex JSON is malformed or violates required OpenVEX fields",
		},
		{
			name: "missing vulnerability",
			payload: openVEXFixture(t, []map[string]any{
				openVEXStatementFixture("", []map[string]any{{"@id": "pkg:apk/openssl@3.1.0"}}, decisionStatusFixed, "fixed"),
			}),
			wantDetail: "openvex JSON is malformed or violates required OpenVEX fields",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, tt.payload)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v, want validation", err)
			}
			if !strings.Contains(err.Error(), tt.wantDetail) {
				t.Fatalf("err = %q, want detail %q", err, tt.wantDetail)
			}
			if tt.notContain != "" && strings.Contains(err.Error(), tt.notContain) {
				t.Fatalf("error leaked raw invalid value %q: %v", tt.notContain, err)
			}
		})
	}
}

func uploadVEXMappingScan(t *testing.T, ctx context.Context, ledger *Ledger, actor domain.Actor, releaseID, vulnerability, component string) domain.VulnerabilityScan {
	t.Helper()
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"`+component+`",
		"release_id":"`+releaseID+`",
		"findings":[{"vulnerability":"`+vulnerability+`","component":"`+component+`","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("upload scan: %v", err)
	}
	return scan
}

func openVEXFixture(t *testing.T, statements []map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        "https://example.test/vex/fixture",
		"author":     "security@example.test",
		"timestamp":  "2026-05-27T12:00:00Z",
		"version":    1,
		"statements": statements,
	})
	if err != nil {
		t.Fatalf("marshal VEX fixture: %v", err)
	}
	return body
}

func openVEXStatementFixture(vulnerability string, products []map[string]any, status, justification string) map[string]any {
	return map[string]any{
		"vulnerability":    map[string]any{"name": vulnerability},
		"products":         products,
		"status":           status,
		"justification":    justification,
		"impact_statement": "Decision detail suitable for customer review.",
		"action_statement": "Review the linked evidence before relying on this decision.",
	}
}

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
