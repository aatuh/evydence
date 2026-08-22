package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestEvidenceIDsForRefsBoundedStopsBeforeUnboundedTraversal(t *testing.T) {
	ledger := NewLedger(Config{})
	ledger.evidence = map[string]domain.EvidenceItem{
		"ev_1": {ID: "ev_1", TenantID: "ten_1", ProductID: "prod_1"},
		"ev_2": {ID: "ev_2", TenantID: "ten_1", ProductID: "prod_1"},
		"ev_3": {ID: "ev_3", TenantID: "ten_1", ProductID: "prod_1"},
	}
	ids, exceeded := ledger.evidenceIDsForRefsBoundedLocked("ten_1", resourceRefs{ProductID: "prod_1"}, "", 2)
	if !exceeded || ids != nil {
		t.Fatalf("bounded traversal ids=%#v exceeded=%t, want nil and true", ids, exceeded)
	}
}

func TestGeneratedReportsRejectOversizedOutput(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	oversized := strings.Repeat("r", MaxGeneratedReportBytes)
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID:   release.ProductID,
		ReleaseID:   release.ID,
		Type:        "security_review",
		Title:       oversized,
		PayloadHash: sampleDigest("oversized-summary"),
	})
	if err != nil {
		t.Fatalf("create oversized evidence: %v", err)
	}
	if _, err := ledger.CreateEvidenceSummary(ctx, actor, CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: release.ID, EvidenceIDs: []string{evidence.ID}}); !errors.Is(err, ErrValidation) {
		t.Fatalf("oversized summary err=%v, want validation", err)
	}
	if _, err := ledger.CreateGraphSnapshot(ctx, actor, CreateGraphSnapshotInput{ProductID: release.ProductID, ReleaseID: release.ID}); !errors.Is(err, ErrValidation) {
		t.Fatalf("oversized graph err=%v, want validation", err)
	}
	if _, err := ledger.CreatePDFReportPackage(ctx, actor, CreatePDFReportPackageInput{ReportType: "release_readiness", ProductID: release.ProductID, ReleaseID: release.ID, Title: oversized}); !errors.Is(err, ErrValidation) {
		t.Fatalf("oversized PDF err=%v, want validation", err)
	}
}

func TestCustomerPackageArchiveRejectsOversizedGeneratedReport(t *testing.T) {
	pkg := domain.CustomerSecurityPackage{
		ID:                 "pkg_oversized",
		ProductID:          "prod_1",
		RedactionProfileID: "rp_1",
		Title:              strings.Repeat("r", MaxGeneratedReportBytes/2),
		State:              "generated",
		Manifest:           map[string]any{},
		ManifestHash:       sampleDigest("oversized-package"),
		SchemaVersion:      domain.CustomerPackageSchemaVersion,
		CreatedAt:          fixedNow(),
	}
	if _, err := customerPackageArchive(pkg); err == nil {
		t.Fatal("customer package archive accepted oversized generated report")
	}
}

func TestCustomerPackageArchiveRejectsSensitiveManifestFields(t *testing.T) {
	pkg := domain.CustomerSecurityPackage{
		ID:                 "pkg_sensitive",
		ProductID:          "prod_1",
		RedactionProfileID: "rp_1",
		Title:              "Customer package",
		State:              "generated",
		Manifest: map[string]any{
			"api_key": "evy-sensitive-package-canary",
		},
		ManifestHash:  sampleDigest("sensitive-package"),
		SchemaVersion: domain.CustomerPackageSchemaVersion,
		CreatedAt:     fixedNow(),
	}
	if _, err := customerPackageArchive(pkg); err == nil {
		t.Fatal("customer package archive accepted a sensitive manifest field")
	}
}

func TestEvidenceLifecycleAuditDetailsRemoveSensitiveCanaries(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID:   release.ProductID,
		ReleaseID:   release.ID,
		Type:        "security_review",
		Title:       "Lifecycle redaction fixture",
		PayloadHash: sampleDigest("lifecycle-redaction"),
	})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}

	canaries := []string{"audit-api-key-canary", "audit-internal-note-canary", "reviewer@example.test"}
	event, err := ledger.RecordEvidenceLifecycleEvent(ctx, actor, evidence.ID, RecordEvidenceLifecycleInput{
		Action: lifecycleAmendment,
		Reason: "amended after EVYDENCE_API_KEY=" + canaries[0],
		Details: map[string]any{
			"internal_notes": canaries[1],
			"reviewer_email": canaries[2],
			"safe_context":   "retained",
		},
	})
	if err != nil {
		t.Fatalf("record lifecycle event: %v", err)
	}
	events, err := ledger.ListEvidenceLifecycleEvents(ctx, actor, evidence.ID)
	if err != nil || len(events) != 1 {
		t.Fatalf("list lifecycle events=%#v err=%v", events, err)
	}
	for _, value := range []domain.EvidenceLifecycleEvent{event, events[0]} {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal lifecycle event: %v", err)
		}
		for _, canary := range canaries {
			if strings.Contains(string(body), canary) {
				t.Fatalf("lifecycle event leaked %q: %s", canary, body)
			}
		}
		if !strings.Contains(string(body), `"safe_context":"retained"`) {
			t.Fatalf("lifecycle event lost safe audit context: %s", body)
		}
	}
}

func TestCustomReportTemplatesAreDataOnlyAndBounded(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	templateCanary := `{{range .Items}}{{template "recursive" .}}{{end}}(a+)+$`
	tpl, err := ledger.CreateCustomReportTemplate(ctx, actor, CreateReportTemplateInput{
		Name:          "Data-only template",
		Version:       "1",
		ReportType:    "evidence",
		AllowedFields: []string{"subject_id"},
		Template:      templateCanary,
	})
	if err != nil {
		t.Fatalf("create data-only report template: %v", err)
	}
	rendered, err := ledger.RenderCustomReport(ctx, actor, RenderReportInput{
		TemplateID:  tpl.ID,
		SubjectType: "release",
		SubjectID:   release.ID,
	})
	if err != nil {
		t.Fatalf("render data-only report: %v", err)
	}
	body, err := json.Marshal(rendered.Output)
	if err != nil {
		t.Fatalf("marshal rendered report: %v", err)
	}
	if strings.Contains(string(body), templateCanary) || !strings.Contains(string(body), release.ID) {
		t.Fatalf("report template was executed or safe fields were lost: %s", body)
	}
	if _, err := ledger.CreateCustomReportTemplate(ctx, actor, CreateReportTemplateInput{
		Name:          "Oversized",
		Version:       "1",
		ReportType:    "evidence",
		AllowedFields: []string{"subject_id"},
		Template:      strings.Repeat("x", int(ReportTemplateRequestLimit)+1),
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("oversized report template err=%v, want validation", err)
	}
}
