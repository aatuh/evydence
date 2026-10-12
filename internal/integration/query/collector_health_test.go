package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type collectorHealthReaderFake struct {
	point      CollectorHealthPoint
	calls      int
	lastTenant string
	err        error
}

func (f *collectorHealthReaderFake) GetCollectorHealthPoint(_ context.Context, tenantID, _ string) (CollectorHealthPoint, error) {
	f.calls++
	f.lastTenant = tenantID
	return f.point, f.err
}

func TestCollectorHealthRequiresTenantWideGrantAndValidatesProjection(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	status, _ := integrationdomain.ParseCollectorStatus(integrationdomain.CollectorStatusActiveValue)
	reader := &collectorHealthReaderFake{point: CollectorHealthPoint{Collector: integrationdomain.Collector{ID: "col_1", TenantID: "ten_1", APIKeyID: "key_1", Status: status, CreatedAt: now}}}
	service, err := NewCollectorHealth(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"collector:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"collector:read"}}}}
	if _, err := service.Report(t.Context(), actor, "col_1"); !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
		t.Fatalf("product grant error=%v calls=%d", err, reader.calls)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_1", Scopes: []string{"collector:read"}}
	report, err := service.Report(t.Context(), actor, "col_1")
	if err != nil || report.SupplyChainStatus != "missing_release_evidence" || len(report.Checks) != 3 || reader.lastTenant != "ten_1" {
		t.Fatalf("tenant report=%#v error=%v", report, err)
	}
	actor.ResourceGrants = nil
	if _, err := service.Report(t.Context(), actor, "col_1"); !errors.Is(err, application.ErrForbidden) || reader.calls != 1 {
		t.Fatalf("revoked grant error=%v calls=%d", err, reader.calls)
	}
	actor = identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"collector:read"}}
	reader.point.Collector.TenantID = "ten_other"
	if _, err := service.Report(t.Context(), actor, "col_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign projection error=%v", err)
	}
	reader.point.Collector.TenantID = "ten_1"
	reader.point.LatestRelease = &integrationdomain.CollectorRelease{ID: "rel_1", TenantID: "ten_other", CollectorID: "col_1", CreatedAt: now}
	if _, err := service.Report(t.Context(), actor, "col_1"); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign release error=%v", err)
	}
	reader.point.LatestRelease.TenantID = "ten_1"
	if _, err := service.Report(t.Context(), actor, "col_1"); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("empty release health error=%v", err)
	}
}

func TestCollectorHealthReportsCurrentReleaseAndPinnedStatus(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	status, _ := integrationdomain.ParseCollectorStatus(integrationdomain.CollectorStatusActiveValue)
	latest := &integrationdomain.CollectorRelease{ID: "rel_latest", TenantID: "ten_1", CollectorID: "col_1", Version: "2", SignatureID: "sig_1", SBOMID: "sbom_1", HealthStatus: "needs_evidence", CreatedAt: now}
	pinned := &integrationdomain.CollectorRelease{ID: "rel_pinned", TenantID: "ten_1", CollectorID: "col_1", Version: "1", Pinned: true, CreatedAt: now.Add(-time.Hour)}
	reader := &collectorHealthReaderFake{point: CollectorHealthPoint{Collector: integrationdomain.Collector{ID: "col_1", TenantID: "ten_1", APIKeyID: "key_1", Status: status, Version: "2", CreatedAt: now}, LatestRelease: latest, PinnedRelease: pinned}}
	service, err := NewCollectorHealth(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"collector:read"}}
	report, err := service.Report(t.Context(), actor, "col_1")
	if err != nil || report.PinnedReleaseID != "rel_pinned" || report.SupplyChainStatus != "needs_evidence" || report.LatestRelease == nil || report.LatestRelease.ID != "rel_latest" || len(report.Checks) != 6 || !report.GeneratedAt.Equal(now) {
		t.Fatalf("report=%#v error=%v", report, err)
	}
}
