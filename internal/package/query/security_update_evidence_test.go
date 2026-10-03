package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type securityUpdateReaderFake struct {
	snapshot SecurityUpdateSnapshot
	calls    int
	tenant   string
	product  string
	release  string
}

func (f *securityUpdateReaderFake) ReadSecurityUpdateSnapshot(_ context.Context, tenant, product, release string) (SecurityUpdateSnapshot, error) {
	f.calls++
	f.tenant, f.product, f.release = tenant, product, release
	return f.snapshot, nil
}

func TestSecurityUpdateEvidenceReportAuthorizesAndAssemblesCurrentSnapshot(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	fixed, _ := riskdomain.ParseDecisionStatus("fixed")
	open, _ := operationsdomain.ParseIncidentStatus("open")
	reader := &securityUpdateReaderFake{snapshot: SecurityUpdateSnapshot{
		TenantID: "ten_a", ProductID: "prod_a", ReleaseID: "rel_a",
		ScanEvidenceIDs: []string{"ev_scan", "ev_scan"},
		Decisions: []riskdomain.VulnerabilityDecision{{
			ID: "dec_a", TenantID: "ten_a", ReleaseID: "rel_a", FindingID: "finding_a", ScanID: "scan_a",
			Vulnerability: "CVE-2026-0001", Status: fixed, Justification: "repaired", Source: "manual",
			EvidenceID: "ev_dec", EvidenceIDs: []string{"ev_dec", "ev_extra"}, VEXDocumentID: "vex_a",
			CreatedAt: now,
		}},
		VEXEvidenceIDs: map[string]string{"vex_a": "ev_vex"},
		Incidents:      []operationsdomain.Incident{{ID: "inc_a", TenantID: "ten_a", ProductID: "prod_a", ReleaseID: "rel_a", Status: open, CreatedAt: now}},
		Tasks:          []operationsdomain.RemediationTask{{ID: "task_a", TenantID: "ten_a", IncidentID: "inc_a", Title: "patch", Status: "open", EvidenceID: "ev_task", CreatedAt: now}},
	}}
	service, err := NewSecurityUpdateEvidence(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{{}, {TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"evidence:read"}}} {
		if _, err := service.Report(t.Context(), actor, "prod_a", "rel_a"); err == nil {
			t.Fatalf("actor=%#v was accepted", actor)
		}
	}
	if reader.calls != 0 {
		t.Fatalf("unauthorized callers reached storage: %d", reader.calls)
	}
	actor := identitydomain.Actor{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"report:read"}}}}
	report, err := service.Report(t.Context(), actor, "prod_a", "rel_a")
	if err != nil || report.ReportType != "security_update_evidence" || report.Summary["security_update_subjects"] != 3 || len(report.FixedDecisions) != 1 || len(report.Incidents) != 1 || len(report.RemediationTasks) != 1 || len(report.EvidenceIDs) != 5 || report.EvidenceIDs[0] != "ev_dec" || !report.GeneratedAt.Equal(now) {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if reader.tenant != "ten_a" || reader.product != "prod_a" || reader.release != "rel_a" {
		t.Fatalf("reader scope=%#v", reader)
	}
	actor.ResourceGrants[0].ResourceID = "prod_b"
	beforeDeniedRead := reader.calls
	if _, err := service.Report(t.Context(), actor, "prod_a", "rel_a"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong product grant err=%v", err)
	}
	if reader.calls != beforeDeniedRead {
		t.Fatalf("wrong product grant reached storage: %d reads", reader.calls-beforeDeniedRead)
	}
	actor.ResourceGrants[0].ResourceID = "prod_a"
	reader.snapshot.TenantID = "ten_b"
	if _, err := service.Report(t.Context(), actor, "prod_a", "rel_a"); !errors.Is(err, ErrSecurityUpdateNotFound) {
		t.Fatalf("foreign projection err=%v", err)
	}
	reader.snapshot.TenantID = "ten_a"
	reader.snapshot.Decisions[0].InternalNotes = "private triage"
	if _, err := service.Report(t.Context(), actor, "prod_a", "rel_a"); !errors.Is(err, ErrSecurityUpdateProjection) {
		t.Fatalf("private decision projection err=%v", err)
	}
	reader.snapshot.Decisions[0].InternalNotes = ""
	delete(reader.snapshot.VEXEvidenceIDs, "vex_a")
	if _, err := service.Report(t.Context(), actor, "prod_a", "rel_a"); !errors.Is(err, ErrSecurityUpdateProjection) {
		t.Fatalf("missing VEX projection err=%v", err)
	}
	reader.snapshot.VEXEvidenceIDs["vex_a"] = "ev_vex"
	reader.snapshot.Tasks[0].TenantID = "ten_b"
	if _, err := service.Report(t.Context(), actor, "prod_a", "rel_a"); !errors.Is(err, ErrSecurityUpdateProjection) {
		t.Fatalf("foreign task projection err=%v", err)
	}
	reader.snapshot.Tasks[0].TenantID = "ten_a"
	reader.snapshot.Incidents[0].ProductID = "prod_b"
	if _, err := service.Report(t.Context(), actor, "prod_a", "rel_a"); !errors.Is(err, ErrSecurityUpdateProjection) {
		t.Fatalf("foreign incident projection err=%v", err)
	}
}
