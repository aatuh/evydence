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

type retentionReaderFake struct {
	calls     int
	tenantID  string
	scopeType string
	scopeID   string
	snapshot  RetentionSnapshot
}

func (f *retentionReaderFake) ReadRetentionRecords(_ context.Context, tenantID, scopeType, scopeID string) (RetentionSnapshot, error) {
	f.calls++
	f.tenantID, f.scopeType, f.scopeID = tenantID, scopeType, scopeID
	return f.snapshot, nil
}

func TestRetentionReportAuthorizesBeforeReading(t *testing.T) {
	reader := &retentionReaderFake{}
	service, err := NewRetentionReport(reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{
		{},
		{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"report:read"}},
		{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"admin"}},
		{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"admin"}}}},
	} {
		_, err := service.Report(t.Context(), actor, "release", "rel_a")
		if actor.TenantID == "" && !errors.Is(err, application.ErrUnauthorized) || actor.TenantID != "" && !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
			t.Fatalf("actor=%#v err=%v read calls=%d", actor, err, reader.calls)
		}
	}
}

func TestRetentionReportPreservesScopeAndRejectsForeignProjection(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	reader := &retentionReaderFake{snapshot: RetentionSnapshot{
		LegalHolds:         []operationsdomain.LegalHold{{ID: "lh_a", TenantID: "ten_a", ScopeType: "release", ScopeID: "rel_a", Reason: "review", Owner: "legal", SchemaVersion: "legal-hold.v1", CreatedAt: now}},
		RetentionOverrides: []operationsdomain.RetentionOverride{{ID: "ro_a", TenantID: "ten_a", ScopeType: "release", ScopeID: "rel_a", Reason: "review", Owner: "legal", SchemaVersion: "retention-override.v1", CreatedAt: now}},
	}}
	service, err := NewRetentionReport(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"admin"}}
	report, err := service.Report(t.Context(), actor, "release", "rel_a")
	if err != nil || reader.tenantID != "ten_a" || reader.scopeType != "release" || reader.scopeID != "rel_a" || len(report.LegalHolds) != 1 || len(report.RetentionOverrides) != 1 || report.ReportType != "retention" || len(report.Limitations) != 1 || !report.GeneratedAt.Equal(now) {
		t.Fatalf("report=%#v reader=%#v err=%v", report, reader, err)
	}
	human := identitydomain.Actor{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "ten_a", Scopes: []string{"admin"}}}}
	if _, err := service.Report(t.Context(), human, "release", "rel_a"); err != nil {
		t.Fatalf("tenant-granted human report: %v", err)
	}
	reader.snapshot.LegalHolds[0].TenantID = "ten_b"
	if _, err := service.Report(t.Context(), actor, "release", "rel_a"); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign hold err=%v", err)
	}
	reader.snapshot.LegalHolds[0].TenantID = "ten_a"
	reader.snapshot.RetentionOverrides[0].ScopeID = "rel_b"
	if _, err := service.Report(t.Context(), actor, "release", "rel_a"); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("wrong-scope override err=%v", err)
	}
}
