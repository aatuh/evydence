package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestVEXFirstReleaseEvidenceFlowEndToEnd(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Design Partner", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}

	product, err := ledger.CreateProduct(ctx, actor, "Demo Payments API", "demo-payments-api")
	if err != nil {
		t.Fatalf("product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "2026.05.0")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	project, err := ledger.CreateProject(ctx, actor, product.ID, "payments-api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "payments-api-linux-amd64.tar.gz", "application/gzip", sampleDigest("artifact"), 123456)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}

	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{
		"bomFormat":"CycloneDX",
		"specVersion":"1.6",
		"components":[
			{"name":"openssl","version":"3.1.0","purl":"pkg:apk/openssl@3.1.0"},
			{"name":"curl","version":"8.0.0","purl":"pkg:apk/curl@8.0.0"}
		]
	}`))
	if err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if sbom.ComponentCount != 2 || sbom.EvidenceID == "" {
		t.Fatalf("sbom parsed metadata = %#v", sbom)
	}

	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/demo-payments-api@sha256:example",
		"release_id":"`+release.ID+`",
		"findings":[
			{"vulnerability":"CVE-2026-1000","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"},
			{"vulnerability":"CVE-2026-1001","component":"pkg:apk/curl@8.0.0","severity":"high","state":"open"}
		]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(scan.Findings) != 2 {
		t.Fatalf("scan findings = %#v", scan.Findings)
	}

	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-1000", []map[string]any{{"@id": "pkg:apk/openssl@3.1.0"}}, decisionStatusNotAffected, "component_not_present"),
	}))
	if err != nil {
		t.Fatalf("vex: %v", err)
	}
	importReport, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("vex import report: %v", err)
	}
	if importReport.DecisionsCreated != 1 || len(importReport.MappingFailures) != 0 {
		t.Fatalf("vex import report = %#v", importReport)
	}
	active := true
	decisions, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: release.ID, Vulnerability: "CVE-2026-1000", Active: &active})
	if err != nil {
		t.Fatalf("list decisions: %v", err)
	}
	if len(decisions) != 1 || decisions[0].Source != "vex" || decisions[0].VEXDocumentID != vex.ID || !decisions[0].CustomerVisible {
		t.Fatalf("vex decisions = %#v", decisions)
	}

	exception, err := ledger.CreateException(ctx, actor, CreateExceptionInput{
		ReleaseID: release.ID,
		FindingID: scan.Findings[1].ID,
		Reason:    "accepted for the pilot release while vendor update is scheduled",
		Owner:     "security",
		ExpiresAt: fixedNow().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("exception: %v", err)
	}
	if _, err := ledger.ApproveException(ctx, actor, exception.ID); err != nil {
		t.Fatalf("approve exception: %v", err)
	}

	build, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{
		ProjectID:   project.ID,
		ReleaseID:   release.ID,
		Provider:    "github_actions",
		CommitSHA:   "0123456789abcdef0123456789abcdef01234567",
		Repository:  "aatuh/evydence",
		WorkflowRef: "aatuh/evydence/.github/workflows/release.yml@refs/heads/main",
		RunID:       "123456789",
		RunAttempt:  1,
		Status:      "passed",
		StartedAt:   fixedNow(),
		Outputs:     []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := ledger.UploadBuildAttestation(ctx, actor, build.ID, dsseForDigest(t, artifact.Digest)); err != nil {
		t.Fatalf("attestation: %v", err)
	}

	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	bundleVerification, err := ledger.VerifySubject(ctx, actor, "release_bundle", bundle.ID)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if bundleVerification.Result != "passed" {
		t.Fatalf("bundle verification = %#v", bundleVerification)
	}

	readiness, err := ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if readiness.Result != "passed" || len(readiness.BlockingFindings) != 0 || len(readiness.AcceptedExceptions) != 1 {
		t.Fatalf("readiness = %#v", readiness)
	}
	if policyCheckByName(t, readiness.Checks, "critical_exploitable_blocks_release").Result != "passed" {
		t.Fatalf("critical policy should pass: %#v", readiness.Checks)
	}

	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{
		Name: "customer release evidence",
		AllowedTypes: []string{
			"artifact", "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "exception", "build", "build_attestation", "release_bundle",
		},
	})
	if err != nil {
		t.Fatalf("redaction profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{
		ProductID:          product.ID,
		ReleaseID:          release.ID,
		RedactionProfileID: profile.ID,
		Title:              "Demo Payments API release evidence",
		ExpiresAt:          fixedNow().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("customer package: %v", err)
	}
	if pkg.ManifestHash == "" || pkg.SchemaVersion != domain.CustomerPackageSchemaVersion {
		t.Fatalf("package metadata = %#v", pkg)
	}
	manifestHash, err := canonicalAnyHash(pkg.Manifest)
	if err != nil {
		t.Fatalf("hash manifest: %v", err)
	}
	if manifestHash != pkg.ManifestHash {
		t.Fatalf("manifest hash = %s, want %s", manifestHash, pkg.ManifestHash)
	}

	archive, err := ledger.ExportCustomerSecurityPackageArchive(ctx, actor, pkg.ID)
	if err != nil {
		t.Fatalf("export archive: %v", err)
	}
	files := packageArchiveFiles(t, archive.Bytes)
	for _, name := range []string{"manifest.json", "package.json", "verification.json", "README.txt", "report.html", "vulnerability-decisions.json"} {
		if strings.TrimSpace(files[name]) == "" {
			t.Fatalf("archive missing %s: %#v", name, files)
		}
	}
	manifestText := files["manifest.json"]
	for _, want := range []string{product.ID, release.ID, artifact.Digest, sbom.ID, scan.ID, vex.ID, decisions[0].ID, exception.ID, bundle.ManifestHash, "audit_chain", "passed"} {
		if !strings.Contains(manifestText, want) {
			t.Fatalf("manifest missing %q: %s", want, manifestText)
		}
	}
	for _, forbidden := range []string{"payload_ref", "object://", "api_key_secret", "private_key_value", "bearer_secret_value", "database_url"} {
		if strings.Contains(strings.ToLower(manifestText), forbidden) {
			t.Fatalf("manifest leaked %q: %s", forbidden, manifestText)
		}
	}
	reportHTML := files["report.html"]
	if !strings.Contains(reportHTML, "Release Summary") || !strings.Contains(reportHTML, "Verification") || strings.Contains(reportHTML, "<script") {
		t.Fatalf("HTML report missing expected content or includes script: %s", reportHTML)
	}
	decisionExport := files["vulnerability-decisions.json"]
	for _, want := range []string{"customer-vulnerability-decisions.v1.0.0", pkg.ID, product.ID, release.ID, decisions[0].ID, "assumptions", "limitations"} {
		if !strings.Contains(decisionExport, want) {
			t.Fatalf("decision export missing %q: %s", want, decisionExport)
		}
	}
	if strings.Contains(decisionExport, "internal_notes") || strings.Contains(decisionExport, "payload_ref") || strings.Contains(decisionExport, "object_key") {
		t.Fatalf("decision export leaked unsafe content: %s", decisionExport)
	}

	auditVerification, err := ledger.VerifySubject(ctx, actor, "audit_chain", "")
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if auditVerification.Result != "passed" {
		body, _ := json.MarshalIndent(auditVerification, "", "  ")
		t.Fatalf("audit chain verification failed: %s", body)
	}
}
