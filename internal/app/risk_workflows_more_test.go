package app

import (
	"context"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestRiskWorkflowEvidenceFormatsAndReports(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: release.ProductID, ReleaseID: release.ID, Type: "security_review", Title: "Review", PayloadHash: sampleDigest("review")})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	incident, err := ledger.CreateIncident(ctx, actor, CreateIncidentInput{ProductID: release.ProductID, ReleaseID: release.ID, Title: "Critical vuln", Severity: "critical"})
	if err != nil {
		t.Fatalf("incident: %v", err)
	}
	if _, err := ledger.RecordIncidentTimelineEvent(ctx, actor, incident.ID, RecordIncidentTimelineInput{EventType: "detected", Summary: "scan detected issue", EvidenceID: evidence.ID}); err != nil {
		t.Fatalf("timeline: %v", err)
	}
	due := fixedNow().Add(24 * time.Hour)
	if _, err := ledger.CreateRemediationTask(ctx, actor, CreateRemediationTaskInput{IncidentID: incident.ID, ReleaseID: release.ID, Title: "Patch", Owner: "security", DueAt: &due, EvidenceID: evidence.ID}); err != nil {
		t.Fatalf("task: %v", err)
	}
	if report, err := ledger.IncidentReport(ctx, actor, incident.ID); err != nil || len(report.Timeline) != 1 || len(report.Tasks) != 1 || len(report.LinkedEvidence) == 0 {
		t.Fatalf("incident report=%#v err=%v", report, err)
	}

	sarif, err := ledger.UploadSecurityScan(ctx, actor, UploadSecurityScanInput{
		ProductID: release.ProductID, ReleaseID: release.ID, ArtifactID: artifact.ID,
		Category: "sast", Format: "sarif", Scanner: "codeql", TargetRef: "git:main",
		Raw: []byte(`{"version":"2.1.0","runs":[{"results":[{"level":"error"},{"level":""}]}]}`),
	})
	if err != nil {
		t.Fatalf("sarif scan: %v", err)
	}
	if sarif.FindingCount != 2 || sarif.Summary["warning"] != 1 {
		t.Fatalf("sarif summary = %#v", sarif)
	}
	secretScan, err := ledger.UploadSecurityScan(ctx, actor, UploadSecurityScanInput{
		ProductID: release.ProductID, ReleaseID: release.ID,
		Category: "secret_scan", Scanner: "gitleaks", TargetRef: "git:main",
		Raw: []byte(`{"findings":[{"severity":"high"}]}`),
	})
	if err != nil {
		t.Fatalf("secret scan: %v", err)
	}
	if !secretScan.Redacted || !secretScan.Quarantined {
		t.Fatalf("secret scan should be redacted/quarantined: %#v", secretScan)
	}
	apiScan, err := ledger.UploadAPISecurityScan(ctx, actor, UploadSecurityScanInput{
		ProductID: release.ProductID, ReleaseID: release.ID, Scanner: "zap", TargetRef: "openapi",
		Raw: []byte(`{"findings":[{"severity":"medium"},{"severity":""}]}`),
	})
	if err != nil {
		t.Fatalf("api security scan: %v", err)
	}
	if apiScan.Category != "api_security" || apiScan.Summary["unknown"] != 1 {
		t.Fatalf("api scan = %#v", apiScan)
	}
	if _, err := ledger.UploadManualSecurityDocument(ctx, actor, UploadManualSecurityDocumentInput{ProductID: release.ProductID, ReleaseID: release.ID, DocumentType: "threat_model", Title: "Threat Model", Sensitivity: "restricted", Raw: []byte("model"), MediaType: "text/plain"}); err != nil {
		t.Fatalf("manual doc: %v", err)
	}

	base, err := ledger.UploadSPDXSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"api","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:oci/api@1.0.0"}]},{"name":"old","versionInfo":"1.0.0"}]}`))
	if err != nil {
		t.Fatalf("base spdx: %v", err)
	}
	target, err := ledger.UploadSPDXSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"api","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:oci/api@1.0.0"}]},{"name":"new","versionInfo":"1.0.0"}]}`))
	if err != nil {
		t.Fatalf("target spdx: %v", err)
	}
	diff, err := ledger.CreateSBOMDiff(ctx, actor, CreateSBOMDiffInput{BaseSBOMID: base.ID, TargetSBOMID: target.ID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("sbom diff: %v", err)
	}
	if diff.UnchangedCount != 1 || len(diff.AddedComponents) != 1 || len(diff.RemovedComponents) != 1 || len(diff.DependencyChanges) != 2 {
		t.Fatalf("diff = %#v", diff)
	}

	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"grype","target_ref":"pkg:oci/api","release_id":"`+release.ID+`","findings":[{"vulnerability":"CVE-2026-0002","component":"api","severity":"critical","state":"open"}]}`))
	if err != nil {
		t.Fatalf("vuln scan: %v", err)
	}
	cdxVEX, err := ledger.UploadCycloneDXVEX(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-2026-0002","analysis":{"state":"resolved","justification":"code_not_present","detail":"fixed","response":["update"]}}]}`))
	if err != nil {
		t.Fatalf("cyclonedx vex: %v", err)
	}
	if cdxVEX.StatusSummary["fixed"] != 1 {
		t.Fatalf("cdx vex = %#v", cdxVEX)
	}
	if _, err := ledger.RecordVulnerabilityWorkflow(ctx, actor, RecordVulnerabilityWorkflowInput{FindingID: scan.Findings[0].ID, Action: "scanner_metadata", Reason: "database version captured"}); err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if posture, err := ledger.VulnerabilityPostureReport(ctx, actor, release.ID); err != nil || posture.OpenCritical != 1 {
		t.Fatalf("posture=%#v err=%v", posture, err)
	}

	baseContract, err := ledger.UploadOpenAPIContract(ctx, actor, release.ProductID, release.ID, "base", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"1"},"paths":{"/v1/a":{"get":{"responses":{"200":{"description":"ok"}}}},"/v1/b":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatalf("base contract: %v", err)
	}
	targetContract, err := ledger.UploadOpenAPIContract(ctx, actor, release.ProductID, release.ID, "target", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"2"},"paths":{"/v1/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatalf("target contract: %v", err)
	}
	contractDiff, err := ledger.CreateContractDiff(ctx, actor, CreateContractDiffInput{BaseContractID: baseContract.ID, TargetContractID: targetContract.ID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("contract diff: %v", err)
	}
	if contractDiff.Result != "breaking" || len(contractDiff.BreakingChanges) != 1 {
		t.Fatalf("contract diff = %#v", contractDiff)
	}

	policy, err := ledger.CreateCustomPolicy(ctx, actor, CreateCustomPolicyInput{Name: "release gates", Version: "1", Rules: []domain.PolicyRule{
		{Name: "metadata", Severity: "low"},
		{Name: "sbom exists", EvidenceType: "sbom", Severity: "high", Required: true},
		{Name: "optional pen test", EvidenceType: "pen_test_report", Severity: "medium", Required: false},
	}})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	eval, err := ledger.EvaluateCustomPolicy(ctx, actor, policy.ID, release.ID)
	if err != nil {
		t.Fatalf("policy eval: %v", err)
	}
	if eval.Result != "passed" || len(eval.Checks) != 3 {
		t.Fatalf("eval = %#v", eval)
	}
}

func TestRiskWorkflowValidationHelpers(t *testing.T) {
	for _, severity := range []string{"low", "medium", "high", "critical"} {
		if !validSeverity(severity) {
			t.Fatalf("valid severity rejected: %s", severity)
		}
	}
	for _, category := range []string{"sast", "dast", "secret_scan", "license_scan", "api_security"} {
		if !validSecurityScanCategory(category) {
			t.Fatalf("valid scan category rejected: %s", category)
		}
	}
	for _, typ := range []string{"threat_model", "security_review", "pen_test_report"} {
		if !validManualDocType(typ) {
			t.Fatalf("valid doc type rejected: %s", typ)
		}
	}
	for _, sensitivity := range []string{"internal", "confidential", "restricted"} {
		if !validSensitivity(sensitivity) {
			t.Fatalf("valid sensitivity rejected: %s", sensitivity)
		}
	}
	for _, action := range []string{"scanner_metadata", "sla_set", "scanner_disagreement", "superseded", "reopened"} {
		if !validVulnWorkflowAction(action) {
			t.Fatalf("valid workflow action rejected: %s", action)
		}
	}
	for _, typ := range []string{"sbom", "vulnerability_scan", "vex", "vulnerability_decision", "artifact", "build", "build_attestation", "openapi_contract", "release_bundle", "exception", "sast", "dast", "secret_scan", "license_scan", "api_security", "deployment", "threat_model", "security_review", "pen_test_report"} {
		if !validPolicyEvidenceType(typ) {
			t.Fatalf("valid policy evidence type rejected: %s", typ)
		}
	}
	if validSeverity("info") || validSecurityScanCategory("container") || validManualDocType("notes") || validSensitivity("public") || validVulnWorkflowAction("ignore") || validPolicyEvidenceType("unknown") {
		t.Fatal("invalid risk workflow helper value accepted")
	}
	if got := cyclonedxAnalysisStatus("resolved"); got != "fixed" {
		t.Fatalf("resolved = %s", got)
	}
	if got := cyclonedxAnalysisStatus("not_affected"); got != "not_affected" {
		t.Fatalf("not_affected = %s", got)
	}
	if got := cyclonedxAnalysisStatus("exploitable"); got != "affected" {
		t.Fatalf("exploitable = %s", got)
	}
	if got := cyclonedxAnalysisStatus("unknown"); got != "" {
		t.Fatalf("unknown = %s", got)
	}
}
