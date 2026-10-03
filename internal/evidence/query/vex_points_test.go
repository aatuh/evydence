package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type vexPointReaderStub struct {
	document VEXDocumentPoint
	report   VEXImportReportPoint
	calls    int
}

func (s *vexPointReaderStub) GetVEXDocumentPoint(_ context.Context, tenantID, id string) (VEXDocumentPoint, error) {
	s.calls++
	if tenantID != "ten_1" || id != "vex_1" {
		return VEXDocumentPoint{}, ErrNotFound
	}
	return s.document, nil
}

func (s *vexPointReaderStub) GetVEXImportReportPoint(_ context.Context, tenantID, id string) (VEXImportReportPoint, error) {
	s.calls++
	if tenantID != "ten_1" || id != "vex_1" {
		return VEXImportReportPoint{}, ErrNotFound
	}
	return s.report, nil
}

func TestVEXPointsRequireTenantGrantAndLinkedReport(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	document := VEXDocumentPoint{ProductID: "prod_1", Document: evidencedomain.VEXDocument{
		ID: "vex_1", TenantID: "ten_1", EvidenceID: "ev_1", ReleaseID: "rel_1", ArtifactID: "art_1",
		Format: "openvex", SchemaVersion: "vex-document.v1", CreatedAt: now,
	}}
	report := evidencedomain.VEXImportReport{
		ID: "report_1", TenantID: "ten_1", VEXDocumentID: "vex_1", EvidenceID: "ev_1",
		ReleaseID: "rel_1", ArtifactID: "art_1", ParserVersion: "openvex.v1", Status: "accepted",
		SchemaVersion: "vex-import-report.v1", CreatedAt: now, UpdatedAt: now,
	}
	reader := &vexPointReaderStub{document: document, report: VEXImportReportPoint{Document: document, Report: report}}
	service, err := NewVEXPoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{"evidence:read"}}}}
	if got, err := service.GetVEXDocument(t.Context(), actor, " vex_1 "); err != nil || got.ID != "vex_1" {
		t.Fatalf("document=%#v error=%v", got, err)
	}
	if got, err := service.GetVEXImportReport(t.Context(), actor, "vex_1"); err != nil || got.ID != "report_1" {
		t.Fatalf("report=%#v error=%v", got, err)
	}
	reader.report.Report.EvidenceID = "ev_other"
	if _, err := service.GetVEXImportReport(t.Context(), actor, "vex_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("unlinked report error=%v", err)
	}
	reader.report.Report.EvidenceID = "ev_1"
	reader.document.Document.TenantID = "ten_other"
	if _, err := service.GetVEXDocument(t.Context(), actor, "vex_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign document projection error=%v", err)
	}
	reader.document.Document.TenantID = "ten_1"
	actor.ResourceGrants[0].ResourceID = "rel_other"
	if _, err := service.GetVEXDocument(t.Context(), actor, "vex_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong document grant error=%v", err)
	}
	if _, err := service.GetVEXImportReport(t.Context(), actor, "vex_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong report grant error=%v", err)
	}
	noScope := actor
	noScope.Scopes = nil
	before := reader.calls
	if _, err := service.GetVEXImportReport(t.Context(), noScope, "vex_1"); !errors.Is(err, application.ErrForbidden) || reader.calls != before {
		t.Fatalf("missing scope error=%v calls=%d", err, reader.calls)
	}
}
