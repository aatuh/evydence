package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestIncidentTimelineAndReportAreTenantScoped(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	incident, err := ledger.CreateIncident(ctx, actor, CreateIncidentInput{ProductID: release.ProductID, ReleaseID: release.ID, Title: "prod outage", Severity: "high"})
	if err != nil {
		t.Fatalf("incident: %v", err)
	}
	event, err := ledger.RecordIncidentTimelineEvent(ctx, actor, incident.ID, RecordIncidentTimelineInput{EventType: "detected", Summary: "monitor alert"})
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	task, err := ledger.CreateRemediationTask(ctx, actor, CreateRemediationTaskInput{IncidentID: incident.ID, Title: "patch service", Owner: "security"})
	if err != nil {
		t.Fatalf("task: %v", err)
	}
	report, err := ledger.IncidentReport(ctx, actor, incident.ID)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if len(report.Timeline) != 1 || report.Timeline[0].ID != event.ID || len(report.Tasks) != 1 || report.Tasks[0].ID != task.ID {
		t.Fatalf("report = %#v, want timeline and task", report)
	}
	_, _, secretB, err := ledger.BootstrapTenant(ctx, "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap B: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, secretB)
	if err != nil {
		t.Fatalf("auth B: %v", err)
	}
	if _, err := ledger.IncidentReport(ctx, actorB, incident.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant incident report err=%v, want not found", err)
	}
}

func TestSecurityScansManualDocsSPDXAndSBOMDiff(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	scan, err := ledger.UploadSecurityScan(ctx, actor, UploadSecurityScanInput{
		ProductID: release.ProductID, ReleaseID: release.ID, ArtifactID: artifact.ID,
		Category: "secret_scan", Format: "generic", Scanner: "trufflehog", TargetRef: artifact.Digest,
		Raw: []byte(`{"findings":[{"severity":"high"}]}`),
	})
	if err != nil {
		t.Fatalf("security scan: %v", err)
	}
	if !scan.Redacted || !scan.Quarantined || scan.Summary["high"] != 1 {
		t.Fatalf("scan = %#v, want redacted quarantined high summary", scan)
	}
	doc, err := ledger.UploadManualSecurityDocument(ctx, actor, UploadManualSecurityDocumentInput{ProductID: release.ProductID, ReleaseID: release.ID, DocumentType: "threat_model", Title: "Threat model", Sensitivity: "restricted", Raw: []byte("sensitive model")})
	if err != nil {
		t.Fatalf("manual doc: %v", err)
	}
	if doc.Sensitivity != "restricted" {
		t.Fatalf("doc sensitivity = %s", doc.Sensitivity)
	}
	base, err := ledger.UploadSPDXSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"openssl","versionInfo":"3.1.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/openssl@3.1.0"}]}]}`))
	if err != nil {
		t.Fatalf("base spdx: %v", err)
	}
	target, err := ledger.UploadSPDXSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"openssl","versionInfo":"3.1.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/openssl@3.1.0"}]},{"name":"curl","versionInfo":"8.0.0"}]}`))
	if err != nil {
		t.Fatalf("target spdx: %v", err)
	}
	diff, err := ledger.CreateSBOMDiff(ctx, actor, CreateSBOMDiffInput{BaseSBOMID: base.ID, TargetSBOMID: target.ID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("sbom diff: %v", err)
	}
	if diff.UnchangedCount != 1 || len(diff.AddedComponents) != 1 || diff.AddedComponents[0].Name != "curl" {
		t.Fatalf("diff = %#v, want curl added", diff)
	}
}

func TestCycloneDXVEXVulnerabilityWorkflowContractDiffAndPolicyV2(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-9999","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("vulnerability scan: %v", err)
	}
	vex, err := ledger.UploadCycloneDXVEX(ctx, actor, release.ID, artifact.ID, []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.6",
		"vulnerabilities":[{"id":"CVE-2026-9999","analysis":{"state":"resolved","justification":"code_not_present","detail":"fixed before release","response":["update"]}}]
	}`))
	if err != nil {
		t.Fatalf("cyclonedx vex: %v", err)
	}
	if vex.Format != "cyclonedx" || vex.StatusSummary["fixed"] != 1 {
		t.Fatalf("vex = %#v, want cyclonedx fixed", vex)
	}
	record, err := ledger.RecordVulnerabilityWorkflow(ctx, actor, RecordVulnerabilityWorkflowInput{FindingID: scan.Findings[0].ID, Action: "scanner_disagreement", Reason: "second scanner disagrees"})
	if err != nil {
		t.Fatalf("workflow: %v", err)
	}
	if record.ReleaseID != release.ID {
		t.Fatalf("workflow release id = %s, want %s", record.ReleaseID, release.ID)
	}
	posture, err := ledger.VulnerabilityPostureReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("posture: %v", err)
	}
	if posture.OpenCritical != 1 || posture.Summary["critical"] != 1 {
		t.Fatalf("posture = %#v", posture)
	}

	baseContract, err := ledger.UploadOpenAPIContract(ctx, actor, release.ProductID, release.ID, "1", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"1"},"paths":{"/v1/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatalf("base contract: %v", err)
	}
	targetContract, err := ledger.UploadOpenAPIContract(ctx, actor, release.ProductID, release.ID, "2", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"2"},"paths":{}}`))
	if err != nil {
		t.Fatalf("target contract: %v", err)
	}
	contractDiff, err := ledger.CreateContractDiff(ctx, actor, CreateContractDiffInput{BaseContractID: baseContract.ID, TargetContractID: targetContract.ID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("contract diff: %v", err)
	}
	if contractDiff.Result != "breaking" || len(contractDiff.BreakingChanges) == 0 {
		t.Fatalf("contract diff = %#v, want breaking", contractDiff)
	}

	policy, err := ledger.CreateCustomPolicy(ctx, actor, CreateCustomPolicyInput{Name: "release evidence", Version: "1", Rules: []domain.PolicyRule{{Name: "requires sbom", EvidenceType: "sbom", Severity: "high", Required: true}}})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	eval, err := ledger.EvaluateCustomPolicy(ctx, actor, policy.ID, release.ID)
	if err != nil {
		t.Fatalf("policy eval: %v", err)
	}
	if eval.Result != "failed" || !strings.Contains(eval.Checks[0].Explanation, "missing") {
		t.Fatalf("eval = %#v, want missing sbom failure", eval)
	}
}
