package query

import (
	"context"
	"errors"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type evidenceFlowReaderStub struct {
	snapshot  EvidenceFlowSnapshot
	err       error
	reads     int
	tenantID  string
	releaseID string
}

func (r *evidenceFlowReaderStub) ReadEvidenceFlowSnapshot(_ context.Context, tenantID, releaseID string) (EvidenceFlowSnapshot, error) {
	r.reads++
	r.tenantID, r.releaseID = tenantID, releaseID
	return r.snapshot, r.err
}

func TestEvidenceFlowUsesTenantScopedSnapshotAndCurrentReleaseGrant(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	reader := &evidenceFlowReaderStub{snapshot: EvidenceFlowSnapshot{
		ReleaseID: "rel_1", ProductID: "prod_1", TenantID: "ten_1",
		Counts: map[string]int{
			"artifact_refs": 1, "passed_builds": 1, "build_attestations": 1,
			"sboms": 1, "vulnerability_scans": 1, "vex_documents": 1,
			"vulnerability_decisions": 1, "release_bundles": 1, "customer_packages": 1,
		},
	}}
	service, err := NewEvidenceFlows(reader, NewCatalogAuthorizer(), application.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{
		TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"release:read"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{"release:read"}}},
	}
	flow, err := service.Plan(t.Context(), actor, " rel_1 ")
	if err != nil || flow.ReleaseID != "rel_1" || flow.ProductID != "prod_1" || flow.Status != "ready_for_review" || flow.Counts["artifact_refs"] != 1 || len(flow.Steps) != 8 || !flow.GeneratedAt.Equal(now) {
		t.Fatalf("flow=%#v err=%v", flow, err)
	}
	if reader.tenantID != actor.TenantID || reader.releaseID != "rel_1" || reader.reads != 1 {
		t.Fatalf("unscoped flow read: %#v", reader)
	}
	actor.ResourceGrants[0].ResourceID = "rel_other"
	if _, err := service.Plan(t.Context(), actor, "rel_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong release grant err=%v, want forbidden", err)
	}
	actor.TenantID = "ten_other"
	if _, err := service.Plan(t.Context(), actor, "rel_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant snapshot err=%v, want not found", err)
	}
}

func TestEvidenceFlowRejectsInvalidInputBeforeReadingCounts(t *testing.T) {
	reader := &evidenceFlowReaderStub{}
	service, err := NewEvidenceFlows(reader, NewCatalogAuthorizer(), application.ClockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"release:read"}}
	if _, err := service.Plan(t.Context(), actor, " "); !errors.Is(err, ErrValidation) || reader.reads != 0 {
		t.Fatalf("blank release err=%v reads=%d", err, reader.reads)
	}
	actor.Scopes = nil
	if _, err := service.Plan(t.Context(), actor, "rel_1"); !errors.Is(err, application.ErrForbidden) || reader.reads != 0 {
		t.Fatalf("missing scope err=%v reads=%d", err, reader.reads)
	}
	actor.Scopes = []string{"release:read"}
	reader.snapshot = EvidenceFlowSnapshot{ReleaseID: "rel_1", TenantID: "ten_1", ProductID: "prod_1", Counts: map[string]int{}}
	flow, err := service.Plan(t.Context(), actor, "rel_1")
	if err != nil || flow.Status != "needs_evidence" || flow.Counts["artifact_refs"] != 0 || flow.Counts["customer_packages"] != 0 {
		t.Fatalf("empty flow=%#v err=%v", flow, err)
	}
}
