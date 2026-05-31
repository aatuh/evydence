package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestManualDecisionCanLinkImportedVEXAndExportCustomerPackage(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	vulnerability := "CVE-2026-0600"
	component := "pkg:apk/openssl@3.1.0"
	scan := uploadVEXMappingScan(t, ctx, ledger, actor, release.ID, vulnerability, component)
	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-9999", []map[string]any{{"@id": "pkg:apk/not-present@1.0.0"}}, decisionStatusFixed, "fixed_elsewhere"),
	}))
	if err != nil {
		t.Fatalf("upload vex: %v", err)
	}
	report, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("import report: %v", err)
	}
	if report.DecisionsCreated != 0 || len(report.MappingFailures) != 1 {
		t.Fatalf("import report should show unmapped VEX statement: %#v", report)
	}

	decision, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "reviewed against imported VEX and release inventory",
		ImpactStatement: "This release is not affected based on the linked VEX review and supporting release evidence.",
		ActionStatement: "No customer action is required for this finding.",
		CustomerVisible: true,
		InternalNotes:   "internal reviewer note",
		VEXDocumentID:   vex.ID,
	})
	if err != nil {
		t.Fatalf("manual decision: %v", err)
	}
	if decision.Source != "api" || decision.VEXDocumentID != vex.ID || decision.EvidenceID != "" {
		t.Fatalf("manual linked decision = %#v", decision)
	}

	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "linked VEX decisions", AllowedTypes: []string{"vulnerability_decision", "vex"}})
	if err != nil {
		t.Fatalf("redaction profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{
		ProductID:          release.ProductID,
		ReleaseID:          release.ID,
		RedactionProfileID: profile.ID,
		Title:              "Linked VEX decision package",
		ExpiresAt:          fixedNow().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("customer package: %v", err)
	}
	body, err := json.Marshal(pkg.Manifest)
	if err != nil {
		t.Fatalf("marshal package manifest: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, decision.ImpactStatement) || !strings.Contains(text, vex.ID) {
		t.Fatalf("package manifest missing linked manual decision fields: %s", body)
	}
	if strings.Contains(text, "internal reviewer note") {
		t.Fatalf("package manifest leaked internal notes: %s", body)
	}
	archive, err := ledger.ExportCustomerSecurityPackageArchive(ctx, actor, pkg.ID)
	if err != nil {
		t.Fatalf("export archive: %v", err)
	}
	htmlReport := packageArchiveFiles(t, archive.Bytes)["report.html"]
	if !strings.Contains(htmlReport, decision.ImpactStatement) || !strings.Contains(htmlReport, vex.ID) {
		t.Fatalf("HTML report missing VEX/decision content: %s", htmlReport)
	}
	if strings.Contains(htmlReport, "internal reviewer note") || strings.Contains(htmlReport, "payload_ref") || strings.Contains(htmlReport, "<script") {
		t.Fatalf("HTML report leaked unsafe content: %s", htmlReport)
	}
}

func TestManualDecisionRejectsForeignReleaseVEXLink(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, releaseA, artifact := setupReleaseRiskFixture(t, ledger)
	releaseB, err := ledger.CreateRelease(ctx, actor, releaseA.ProductID, "2.0.0")
	if err != nil {
		t.Fatalf("release B: %v", err)
	}
	scan := uploadVEXMappingScan(t, ctx, ledger, actor, releaseA.ID, "CVE-2026-0601", "pkg:apk/openssl@3.1.0")
	vex, err := ledger.UploadVEX(ctx, actor, releaseB.ID, artifact.ID, openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-0601", []map[string]any{{"@id": "pkg:apk/openssl@3.1.0"}}, decisionStatusFixed, "fixed"),
	}))
	if err != nil {
		t.Fatalf("upload release B vex: %v", err)
	}

	_, err = ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "manual review",
		ImpactStatement: "Customer-safe review statement.",
		CustomerVisible: true,
		VEXDocumentID:   vex.ID,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign release VEX link err=%v, want not found", err)
	}
}

func TestManualCustomerVisibleDecisionRequiresCustomerStatement(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	scan := uploadVEXMappingScan(t, ctx, ledger, actor, release.ID, "CVE-2026-0602", "pkg:apk/openssl@3.1.0")

	_, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "manual review",
		CustomerVisible: true,
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("customer-visible manual decision err=%v, want validation", err)
	}
}
