package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type incidentReportReaderFake struct {
	snapshot IncidentReportSnapshot
	calls    int
	tenantID string
	id       string
}

func (f *incidentReportReaderFake) ReadIncidentReport(_ context.Context, tenantID, id string) (IncidentReportSnapshot, error) {
	f.calls++
	f.tenantID, f.id = tenantID, id
	return f.snapshot, nil
}

func TestIncidentReportAuthorizesScopeAndCurrentResourceGrant(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	open, _ := operationsdomain.ParseIncidentStatus("open")
	reader := &incidentReportReaderFake{snapshot: IncidentReportSnapshot{Incident: operationsdomain.Incident{
		ID: "inc_a", TenantID: "ten_a", ProductID: "prod_a", ReleaseID: "rel_a", Status: open,
	}}}
	service, err := NewIncidentReport(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{
		{},
		{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"release:read"}},
		{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"incident:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_b", Scopes: []string{"incident:read"}}}},
	} {
		_, err := service.Report(t.Context(), actor, "inc_a")
		if actor.TenantID == "" && !errors.Is(err, application.ErrUnauthorized) || actor.TenantID != "" && !errors.Is(err, application.ErrForbidden) {
			t.Fatalf("actor=%#v err=%v", actor, err)
		}
	}
	if reader.calls != 1 {
		t.Fatalf("scope failure reached reader: calls=%d", reader.calls)
	}
	for _, grant := range []identitydomain.ResourceGrant{
		{ResourceType: "tenant", ResourceID: "ten_a", Scopes: []string{"incident:read"}},
		{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"incident:read"}},
		{ResourceType: "release", ResourceID: "rel_a", Scopes: []string{"incident:read"}},
	} {
		actor := identitydomain.Actor{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"incident:read"}, ResourceGrants: []identitydomain.ResourceGrant{grant}}
		if _, err := service.Report(t.Context(), actor, "inc_a"); err != nil {
			t.Fatalf("grant=%#v err=%v", grant, err)
		}
	}
	if reader.tenantID != "ten_a" || reader.id != "inc_a" {
		t.Fatalf("reader scope=%#v", reader)
	}
}

func TestIncidentReportRejectsForeignProjectionAndKeepsOrderedEvidence(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	closed, _ := operationsdomain.ParseIncidentStatus("closed")
	reader := &incidentReportReaderFake{snapshot: IncidentReportSnapshot{
		Incident: operationsdomain.Incident{ID: "inc_a", TenantID: "ten_a", ProductID: "prod_a", Status: closed},
		Timeline: []operationsdomain.IncidentTimelineEvent{
			{ID: "ev_b", TenantID: "ten_a", IncidentID: "inc_a", EvidenceID: "evidence_b", OccurredAt: now.Add(time.Minute)},
			{ID: "ev_a", TenantID: "ten_a", IncidentID: "inc_a", EvidenceID: "evidence_a", OccurredAt: now},
		},
		Tasks: []operationsdomain.RemediationTask{{ID: "task_a", TenantID: "ten_a", IncidentID: "inc_a", EvidenceID: "evidence_b", CreatedAt: now}},
	}}
	service, err := NewIncidentReport(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"incident:read"}}
	report, err := service.Report(t.Context(), actor, "inc_a")
	if err != nil || report.Result != "closed" || len(report.Timeline) != 2 || report.Timeline[0].ID != "ev_a" || len(report.Tasks) != 1 || len(report.LinkedEvidence) != 3 || report.LinkedEvidence[0] != "evidence_a" || report.LinkedEvidence[1] != "evidence_b" || report.LinkedEvidence[2] != "evidence_b" || !report.GeneratedAt.Equal(now) {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	reader.snapshot.Timeline[0].TenantID = "ten_b"
	if _, err := service.Report(t.Context(), actor, "inc_a"); !errors.Is(err, ErrIncidentReportProjection) {
		t.Fatalf("foreign event err=%v", err)
	}
	reader.snapshot.Timeline[0].TenantID = "ten_a"
	reader.snapshot.Incident.TenantID = "ten_b"
	if _, err := service.Report(t.Context(), actor, "inc_a"); !errors.Is(err, ErrIncidentReportNotFound) {
		t.Fatalf("foreign incident err=%v", err)
	}
}
