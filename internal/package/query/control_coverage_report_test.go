package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type controlCoverageReaderFake struct {
	snapshot ControlCoverageSnapshot
	calls    int
}

func (f *controlCoverageReaderFake) ReadControlCoverageSnapshot(context.Context, string, string, string, string, time.Time) (ControlCoverageSnapshot, error) {
	f.calls++
	return f.snapshot, nil
}

func TestControlCoverageReportEvaluatesOneAuthorizedSnapshot(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	reader := &controlCoverageReaderFake{snapshot: ControlCoverageSnapshot{
		TenantID: "ten_a", FrameworkID: "fw_a", ScopeProductID: "prod_a", ScopeReleaseID: "rel_a",
		Controls: []riskdomain.SecurityControl{
			{ID: "c_stale", TenantID: "ten_a", FrameworkID: "fw_a", Code: "B", Title: "Scan", EvidenceRequirements: []riskdomain.ControlEvidenceRequirement{{Type: "vulnerability_scan", Required: true, FreshnessDays: 30}}},
			{ID: "c_ok", TenantID: "ten_a", FrameworkID: "fw_a", Code: "A", Title: "SBOM", EvidenceRequirements: []riskdomain.ControlEvidenceRequirement{{Type: "sbom", Required: true}}},
			{ID: "c_unknown", TenantID: "ten_a", FrameworkID: "fw_a", Code: "D", Title: "Unknown"},
			{ID: "c_waived", TenantID: "ten_a", FrameworkID: "fw_a", Code: "C", Title: "Waived", EvidenceRequirements: []riskdomain.ControlEvidenceRequirement{{Type: "build", Required: true}}},
		},
		Links: []ControlCoverageLink{
			{Link: riskdomain.ControlEvidence{ID: "link_b", TenantID: "ten_a", ControlID: "c_stale", EvidenceType: "vulnerability_scan", SubjectType: "vulnerability_scan", SubjectID: "scan_a", Confidence: "low"}, SubjectObservedAt: now.Add(-31 * 24 * time.Hour)},
			{Link: riskdomain.ControlEvidence{ID: "link_a", TenantID: "ten_a", ControlID: "c_ok", EvidenceType: "sbom", SubjectType: "sbom", SubjectID: "sbom_a", Confidence: "high"}, SubjectObservedAt: now},
		},
		Exceptions: []riskdomain.Exception{{ID: "ex_a", TenantID: "ten_a", ReleaseID: "rel_a", ControlID: "c_waived", Reason: "reviewed", Approved: true, ExpiresAt: now.Add(time.Hour)}},
	}}
	service, err := NewControlCoverageReport(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{
		{},
		{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"controls:read"}},
		{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_b", Scopes: []string{"report:read"}}}},
	} {
		if _, err := service.Coverage(t.Context(), actor, ControlCoverageFilter{FrameworkID: "fw_a", ProductID: "prod_a", ReleaseID: "rel_a"}); err == nil {
			t.Fatalf("unauthorized actor %#v", actor)
		}
	}
	if reader.calls != 0 {
		t.Fatalf("unauthorized report reached storage: %d", reader.calls)
	}
	actor := identitydomain.Actor{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"report:read"}}}}
	report, err := service.Coverage(t.Context(), actor, ControlCoverageFilter{FrameworkID: "fw_a", ProductID: "prod_a", ReleaseID: "rel_a"})
	if err != nil || report.ReportType != "control_coverage" || report.Result != "failed" || len(report.Controls) != 4 || report.Controls[0].ControlID != "c_ok" || report.Controls[0].Status != "satisfied" || report.Controls[0].Confidence != "high" || report.Controls[1].Status != "partial" || report.Controls[1].Missing[0] != "fresh_vulnerability_scan" || report.Controls[2].Status != "waived" || report.Controls[3].Status != "unknown" || len(report.MissingEvidence) != 2 || len(report.AcceptedExceptions) != 1 || !report.GeneratedAt.Equal(now) {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	cra, err := service.CRAReadiness(t.Context(), actor, "prod_a", "rel_a")
	if err != nil || cra.ReportType != "cra_readiness" || cra.Result != "failed" || len(cra.Controls) != 4 || len(cra.AcceptedExceptions) != 1 {
		t.Fatalf("CRA report=%#v err=%v", cra, err)
	}
	reader.snapshot.Links[0].Link.TenantID = "ten_b"
	if _, err := service.Coverage(t.Context(), actor, ControlCoverageFilter{FrameworkID: "fw_a", ProductID: "prod_a", ReleaseID: "rel_a"}); !errors.Is(err, ErrControlCoverageProjection) {
		t.Fatalf("foreign link err=%v", err)
	}
	reader.snapshot.Links[0].Link.TenantID = "ten_a"
	reader.snapshot.Exceptions[0].ExpiresAt = now.Add(-time.Hour)
	if _, err := service.Coverage(t.Context(), actor, ControlCoverageFilter{FrameworkID: "fw_a", ProductID: "prod_a", ReleaseID: "rel_a"}); !errors.Is(err, ErrControlCoverageProjection) {
		t.Fatalf("expired exception err=%v", err)
	}
	reader.snapshot.Exceptions[0].ExpiresAt = now.Add(time.Hour)
	reader.snapshot.ScopeProductID = "prod_b"
	if _, err := service.Coverage(t.Context(), actor, ControlCoverageFilter{FrameworkID: "fw_a", ProductID: "prod_a", ReleaseID: "rel_a"}); !errors.Is(err, ErrControlCoverageNotFound) {
		t.Fatalf("wrong product parent err=%v", err)
	}
}

func TestControlCoverageTenantWideRequiresTenantGrantBeforeRead(t *testing.T) {
	reader := &controlCoverageReaderFake{}
	service, err := NewControlCoverageReport(reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"report:read"}}}}
	if _, err := service.Coverage(t.Context(), actor, ControlCoverageFilter{}); !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
		t.Fatalf("tenant-wide report err=%v reads=%d", err, reader.calls)
	}
}

func TestControlCoverageProductScopeRejectsEmptyReleaseGrant(t *testing.T) {
	reader := &controlCoverageReaderFake{}
	service, err := NewControlCoverageReport(reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{
		TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"report:read"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "", Scopes: []string{"report:read"}}},
	}
	if _, err := service.Coverage(t.Context(), actor, ControlCoverageFilter{ProductID: "prod_a"}); !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
		t.Fatalf("empty release grant authorized product-wide report: err=%v reads=%d", err, reader.calls)
	}
}

func TestControlCoverageDoesNotWaiveOtherReleaseOrPassEmptyFramework(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	reader := &controlCoverageReaderFake{snapshot: ControlCoverageSnapshot{
		TenantID: "ten_a", FrameworkID: "fw_a", ScopeProductID: "prod_a",
		Controls: []riskdomain.SecurityControl{{
			ID: "c_a", TenantID: "ten_a", FrameworkID: "fw_a", Code: "A", Title: "Required",
			EvidenceRequirements: []riskdomain.ControlEvidenceRequirement{{Type: "sbom", Required: true}},
		}},
		Exceptions: []riskdomain.Exception{{ID: "ex_other_release", TenantID: "ten_a", ControlID: "c_a", ReleaseID: "rel_other", Approved: true, ExpiresAt: now.Add(time.Hour)}},
	}}
	service, err := NewControlCoverageReport(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"report:read"}}}}
	report, err := service.Coverage(t.Context(), actor, ControlCoverageFilter{ProductID: "prod_a"})
	if err != nil || report.Controls[0].Status != "missing" || report.Result != "failed" {
		t.Fatalf("cross-release waiver report=%#v err=%v", report, err)
	}
	reader.snapshot.Controls = nil
	reader.snapshot.Exceptions = nil
	report, err = service.Coverage(t.Context(), actor, ControlCoverageFilter{ProductID: "prod_a"})
	if err != nil || report.Result != "unknown" {
		t.Fatalf("empty framework report=%#v err=%v", report, err)
	}
}

func TestControlCoverageWaiverIsDeterministicAndRejectsBadStoredRules(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	reader := &controlCoverageReaderFake{snapshot: ControlCoverageSnapshot{
		TenantID: "ten_a", FrameworkID: "fw_a", ScopeProductID: "prod_a", ScopeReleaseID: "rel_a",
		Controls: []riskdomain.SecurityControl{{
			ID: "c_a", TenantID: "ten_a", FrameworkID: "fw_a", Code: "A", Title: "Required",
			EvidenceRequirements: []riskdomain.ControlEvidenceRequirement{{Type: "sbom", Required: true}},
		}},
		Exceptions: []riskdomain.Exception{
			{ID: "ex_z", TenantID: "ten_a", ControlID: "c_a", ReleaseID: "rel_a", Reason: "later", Approved: true, ExpiresAt: now.Add(time.Hour)},
			{ID: "ex_a", TenantID: "ten_a", ControlID: "c_a", ReleaseID: "rel_a", Reason: "first", Approved: true, ExpiresAt: now.Add(time.Hour)},
		},
	}}
	service, err := NewControlCoverageReport(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"report:read"}}
	filter := ControlCoverageFilter{ProductID: "prod_a", ReleaseID: "rel_a"}
	report, err := service.Coverage(t.Context(), actor, filter)
	if err != nil || report.Controls[0].Status != "waived" || report.Controls[0].Limitations[0] != "first" {
		t.Fatalf("nondeterministic waiver report=%#v err=%v", report, err)
	}
	reader.snapshot.Exceptions = nil
	reader.snapshot.Controls[0].EvidenceRequirements[0].Type = "unknown"
	if _, err := service.Coverage(t.Context(), actor, filter); !errors.Is(err, ErrControlCoverageProjection) {
		t.Fatalf("unsupported stored requirement err=%v", err)
	}
	reader.snapshot.Controls = make([]riskdomain.SecurityControl, MaxControlCoverageEntries+1)
	if _, err := service.Coverage(t.Context(), actor, filter); !errors.Is(err, ErrControlCoverageCapacity) {
		t.Fatalf("oversized projection err=%v", err)
	}
}
