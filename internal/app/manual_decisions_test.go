package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
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

func TestManualDecisionSupportingRefsAreScopedAndCustomerSafe(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	scan := uploadVEXMappingScan(t, ctx, ledger, actor, release.ID, "CVE-2026-0610", "pkg:apk/openssl@3.1.0")
	exception, err := ledger.CreateException(ctx, actor, CreateExceptionInput{ReleaseID: release.ID, FindingID: scan.Findings[0].ID, Reason: "temporary customer-visible exception", Owner: "security", ExpiresAt: fixedNow().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("exception: %v", err)
	}
	if _, err := ledger.ApproveException(ctx, actor, exception.ID); err != nil {
		t.Fatalf("approve exception: %v", err)
	}
	waiver, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "documented risk", Reason: "release-scoped waiver", ExpiresAt: fixedNow().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("waiver: %v", err)
	}
	if _, err := ledger.ApproveWaiver(ctx, actor, waiver.ID); err != nil {
		t.Fatalf("approve waiver: %v", err)
	}
	approval, err := ledger.CreateApprovalRecord(ctx, actor, CreateApprovalInput{SubjectType: "release", SubjectID: release.ID, Decision: "approved", Reason: "release risk reviewed"})
	if err != nil {
		t.Fatalf("approval: %v", err)
	}
	incident, err := ledger.CreateIncident(ctx, actor, CreateIncidentInput{ProductID: release.ProductID, ReleaseID: release.ID, Title: "Patch tracking", Severity: "medium", OpenedAt: fixedNow()})
	if err != nil {
		t.Fatalf("incident: %v", err)
	}
	task, err := ledger.CreateRemediationTask(ctx, actor, CreateRemediationTaskInput{ReleaseID: release.ID, Title: "Monitor upstream fix", Owner: "security"})
	if err != nil {
		t.Fatalf("task: %v", err)
	}
	ledger.bundles["bundle_support"] = domain.ReleaseBundle{ID: "bundle_support", TenantID: actor.TenantID, ReleaseID: release.ID, State: "generated", ManifestHash: sampleDigest("bundle"), CreatedAt: fixedNow()}

	decision, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusAffected,
		Justification:   "affected while a follow-up fix is tracked",
		ImpactStatement: "The finding is tracked with linked release-scoped decision support.",
		ActionStatement: "Review the linked exception, waiver, approval, bundle, incident, and remediation task before relying on the release.",
		CustomerVisible: true,
		InternalNotes:   "private support note",
		SupportingRefs: []domain.SubjectRef{
			{Type: "waiver", ID: waiver.ID},
			{Type: "release_bundle", ID: "bundle_support"},
			{Type: "exception", ID: exception.ID},
			{Type: "remediation_task", ID: task.ID},
			{Type: "incident", ID: incident.ID},
			{Type: "approval", ID: approval.ID},
		},
	})
	if err != nil {
		t.Fatalf("decision: %v", err)
	}
	gotTypes := []string{}
	for _, ref := range decision.SupportingRefs {
		gotTypes = append(gotTypes, ref.Type)
		if ref.Digest != "" {
			t.Fatalf("supporting ref leaked digest: %#v", decision.SupportingRefs)
		}
	}
	if strings.Join(gotTypes, ",") != "approval,exception,incident,release_bundle,remediation_task,waiver" {
		t.Fatalf("supporting refs not normalized deterministically: %#v", decision.SupportingRefs)
	}
	report, err := ledger.VulnerabilityDecisionSummaryReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("summary report: %v", err)
	}
	if len(report.Decisions) != 1 || len(report.Decisions[0].SupportingRefs) != len(decision.SupportingRefs) {
		t.Fatalf("summary supporting refs = %#v", report.Decisions)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "decision support refs", AllowedTypes: []string{"vulnerability_decision"}})
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{
		ProductID:          release.ProductID,
		ReleaseID:          release.ID,
		RedactionProfileID: profile.ID,
		Title:              "Decision support refs",
		ExpiresAt:          fixedNow().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("package: %v", err)
	}
	body, err := json.Marshal(pkg.Manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	text := string(body)
	for _, want := range []string{"supporting_refs", approval.ID, exception.ID, waiver.ID, incident.ID, task.ID, "bundle_support"} {
		if !strings.Contains(text, want) {
			t.Fatalf("manifest missing %q in %s", want, body)
		}
	}
	if strings.Contains(text, "private support note") {
		t.Fatalf("manifest leaked internal notes: %s", body)
	}
}

func TestManualDecisionRejectsInvalidSupportingRefs(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, releaseA, _ := setupReleaseRiskFixture(t, ledger)
	releaseB, err := ledger.CreateRelease(ctx, actor, releaseA.ProductID, "2.0.0")
	if err != nil {
		t.Fatalf("release B: %v", err)
	}
	scan := uploadVEXMappingScan(t, ctx, ledger, actor, releaseA.ID, "CVE-2026-0611", "pkg:apk/openssl@3.1.0")
	otherException, err := ledger.CreateException(ctx, actor, CreateExceptionInput{ReleaseID: releaseB.ID, Reason: "wrong release", Owner: "security", ExpiresAt: fixedNow().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("other exception: %v", err)
	}

	_, err = ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusAffected,
		Justification:   "manual review",
		ImpactStatement: "Customer-safe review statement.",
		CustomerVisible: true,
		SupportingRefs:  []domain.SubjectRef{{Type: "exception", ID: otherException.ID}},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-release supporting ref err=%v, want not found", err)
	}

	_, err = ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusAffected,
		Justification:   "manual review",
		ImpactStatement: "Customer-safe review statement.",
		CustomerVisible: true,
		SupportingRefs:  []domain.SubjectRef{{Type: "release_bundle", ID: "bundle_missing", Digest: sampleDigest("support")}},
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("supporting ref digest err=%v, want validation", err)
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
