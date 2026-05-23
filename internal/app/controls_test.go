package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestControlFrameworkControlEvidenceAndCoverageFlow(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:oci/payments-api"}]}`))
	if err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if _, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"grype","target_ref":"pkg:oci/payments-api","release_id":"`+release.ID+`","findings":[]}`)); err != nil {
		t.Fatalf("scan: %v", err)
	}

	framework, err := ledger.CreateControlFramework(ctx, actor, CreateControlFrameworkInput{Name: "CRA readiness", Slug: "evydence-cra-readiness", Version: "2026.05", Description: "technical readiness controls"})
	if err != nil {
		t.Fatalf("framework: %v", err)
	}
	if _, err := ledger.CreateControlFramework(ctx, actor, CreateControlFrameworkInput{Name: "CRA readiness", Slug: "evydence-cra-readiness", Version: "2026.05"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate framework err=%v, want conflict", err)
	}
	control, err := ledger.CreateSecurityControl(ctx, actor, CreateSecurityControlInput{
		FrameworkID: framework.ID,
		Code:        "CRA-SBOM",
		Title:       "SBOM is recorded",
		Objective:   "Release evidence includes a linked SBOM.",
		EvidenceRequirements: []domain.ControlEvidenceRequirement{{
			Type:          "sbom",
			FreshnessDays: 90,
			Required:      true,
		}},
		Limitations: []string{"Presence of an SBOM does not prove SBOM completeness."},
	})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	report, err := ledger.ControlCoverageReport(ctx, actor, ControlCoverageReportInput{FrameworkID: framework.ID, ProductID: release.ProductID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("coverage missing: %v", err)
	}
	if report.Result != "failed" || len(report.Controls) != 1 || report.Controls[0].Status != "missing" {
		t.Fatalf("expected missing coverage before link, got %#v", report)
	}
	link, err := ledger.LinkControlEvidence(ctx, actor, control.ID, LinkControlEvidenceInput{
		EvidenceType: "sbom",
		SubjectType:  "sbom",
		SubjectID:    sbom.ID,
		ProductID:    release.ProductID,
		ReleaseID:    release.ID,
		Confidence:   "high",
		Notes:        "CycloneDX payload linked to release artifact.",
	})
	if err != nil {
		t.Fatalf("link control evidence: %v", err)
	}
	second, err := ledger.LinkControlEvidence(ctx, actor, control.ID, LinkControlEvidenceInput{
		EvidenceType: "sbom",
		SubjectType:  "sbom",
		SubjectID:    sbom.ID,
		ProductID:    release.ProductID,
		ReleaseID:    release.ID,
		Confidence:   "high",
	})
	if err != nil {
		t.Fatalf("duplicate link: %v", err)
	}
	if second.ID != link.ID {
		t.Fatalf("duplicate link should replay existing id=%s got=%s", link.ID, second.ID)
	}
	report, err = ledger.ControlCoverageReport(ctx, actor, ControlCoverageReportInput{FrameworkID: framework.ID, ProductID: release.ProductID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("coverage linked: %v", err)
	}
	if report.Result != "passed" || report.Controls[0].Status != "satisfied" || report.Controls[0].Confidence != "high" {
		t.Fatalf("expected satisfied high coverage, got %#v", report)
	}
	cra, err := ledger.CRAReadinessReport(ctx, actor, CRAReadinessReportInput{ProductID: release.ProductID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("cra report: %v", err)
	}
	body := strings.ToLower(strings.Join(append(cra.Assumptions, cra.Limitations...), " "))
	for _, forbidden := range []string{"automatically compliant", "certified secure", "legally sufficient", "sbom is complete"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("CRA report contains forbidden claim %q: %#v", forbidden, cra)
		}
	}
}

func TestControlValidationScopeAndWaivedCoverage(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actorA, releaseA, artifactA := setupReleaseRiskFixture(t, ledger)
	actorB, _, _ := setupReleaseRiskFixture(t, ledger)
	framework, err := ledger.CreateControlFramework(ctx, actorA, CreateControlFrameworkInput{Name: "NIST SSDF lite", Version: "1.1"})
	if err != nil {
		t.Fatalf("framework: %v", err)
	}
	if _, err := ledger.CreateSecurityControl(ctx, actorA, CreateSecurityControlInput{
		FrameworkID: framework.ID,
		Code:        "BAD",
		Title:       "Bad",
		Objective:   "Bad",
		EvidenceRequirements: []domain.ControlEvidenceRequirement{{
			Type:          "unsupported",
			FreshnessDays: 30,
			Required:      true,
		}},
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("unsupported evidence type err=%v, want validation", err)
	}
	if _, err := ledger.CreateSecurityControl(ctx, actorB, CreateSecurityControlInput{FrameworkID: framework.ID, Code: "X", Title: "X", Objective: "X"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant framework err=%v, want not found", err)
	}
	control, err := ledger.CreateSecurityControl(ctx, actorA, CreateSecurityControlInput{
		FrameworkID: framework.ID,
		Code:        "VULN",
		Title:       "Vulnerability scan is reviewed",
		Objective:   "Release has vulnerability evidence.",
		EvidenceRequirements: []domain.ControlEvidenceRequirement{{
			Type:          "vulnerability_scan",
			FreshnessDays: 30,
			Required:      true,
		}},
	})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	exception, err := ledger.CreateException(ctx, actorA, CreateExceptionInput{ReleaseID: releaseA.ID, ControlID: control.ID, Reason: "temporary control waiver", Owner: "security", ExpiresAt: fixedNow().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("exception: %v", err)
	}
	report, err := ledger.ControlCoverageReport(ctx, actorA, ControlCoverageReportInput{FrameworkID: framework.ID, ProductID: releaseA.ProductID, ReleaseID: releaseA.ID})
	if err != nil {
		t.Fatalf("coverage unapproved: %v", err)
	}
	if report.Controls[0].Status != "missing" {
		t.Fatalf("unapproved exception should not waive control: %#v", report.Controls[0])
	}
	if _, err := ledger.ApproveException(ctx, actorA, exception.ID); err != nil {
		t.Fatalf("approve exception: %v", err)
	}
	report, err = ledger.ControlCoverageReport(ctx, actorA, ControlCoverageReportInput{FrameworkID: framework.ID, ProductID: releaseA.ProductID, ReleaseID: releaseA.ID})
	if err != nil {
		t.Fatalf("coverage waived: %v", err)
	}
	if report.Result != "passed" || report.Controls[0].Status != "waived" || len(report.AcceptedExceptions) != 1 {
		t.Fatalf("approved control exception should waive coverage: %#v", report)
	}
	sbom, err := ledger.UploadSBOM(ctx, actorA, releaseA.ID, artifactA.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"}]}`))
	if err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if _, err := ledger.LinkControlEvidence(ctx, actorB, control.ID, LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "sbom", SubjectID: sbom.ID, ProductID: releaseA.ProductID, ReleaseID: releaseA.ID, Confidence: "high"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant link err=%v, want not found", err)
	}
}

func TestControlStatePersistsAcrossRestart(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	ledger, err := NewLedgerWithError(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"}]}`))
	if err != nil {
		t.Fatalf("sbom: %v", err)
	}
	framework, err := ledger.CreateControlFramework(ctx, actor, CreateControlFrameworkInput{Name: "Persisted controls", Version: "1"})
	if err != nil {
		t.Fatalf("framework: %v", err)
	}
	control, err := ledger.CreateSecurityControl(ctx, actor, CreateSecurityControlInput{
		FrameworkID: framework.ID,
		Code:        "PERSIST",
		Title:       "Persisted",
		Objective:   "Persisted",
		EvidenceRequirements: []domain.ControlEvidenceRequirement{{
			Type:     "sbom",
			Required: true,
		}},
	})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, err := ledger.LinkControlEvidence(ctx, actor, control.ID, LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "sbom", SubjectID: sbom.ID, ProductID: release.ProductID, ReleaseID: release.ID, Confidence: "high"}); err != nil {
		t.Fatalf("link: %v", err)
	}
	restarted, err := NewLedgerWithError(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	report, err := restarted.ControlCoverageReport(ctx, actor, ControlCoverageReportInput{FrameworkID: framework.ID, ProductID: release.ProductID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("coverage after restart: %v", err)
	}
	if report.Result != "passed" {
		t.Fatalf("coverage after restart = %#v", report)
	}
}
