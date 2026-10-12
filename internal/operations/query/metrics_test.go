package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type metricsReaderFake struct {
	tenantID      string
	includeOutbox bool
	calls         int
	snapshot      MetricsSnapshot
}

func (f *metricsReaderFake) ReadMetricsSnapshot(_ context.Context, tenantID string, includeOutbox bool) (MetricsSnapshot, error) {
	f.calls++
	f.tenantID, f.includeOutbox = tenantID, includeOutbox
	snapshot := f.snapshot
	if !includeOutbox {
		snapshot.Outbox = nil
	}
	return snapshot, nil
}

func TestMetricsAuthorizesBeforeTenantOrGlobalRead(t *testing.T) {
	reader := &metricsReaderFake{}
	service, err := NewMetrics(reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{
		{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"report:read"}},
		{TenantID: "ten_a", UserID: "usr_a", Scopes: []string{"admin"}},
	} {
		if _, err := service.Snapshot(t.Context(), actor); !errors.Is(err, application.ErrForbidden) {
			t.Fatalf("actor=%#v err=%v, want forbidden", actor, err)
		}
	}
	if reader.calls != 0 {
		t.Fatalf("unauthorized metrics made %d reads", reader.calls)
	}
}

func TestMetricsKeepsTenantAndGlobalProjectionsSeparateAndPayloadFree(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	reader := &metricsReaderFake{snapshot: MetricsSnapshot{
		ResourceCounts: map[string]int{
			"audit_chain_entries": 2, "artifact_signatures": 0, "cosign_verifications": 0,
			"evidence": 1, "merkle_batches": 0, "object_retention_policies": 0,
			"release_bundles": 1, "transparency_checkpoints": 0,
		},
		CustomerPortalFailedAccessCount:  3,
		CustomerPortalRevokedAccessCount: 1,
		Reconciliation:                   ReconciliationCounts{Runs: 1, ScannedPayloads: 2, LastRunAt: now.Add(-time.Minute)},
		Outbox:                           &OutboxCounts{PendingJobs: 2, RunningJobs: 1, TerminalJobs: 1, OldestPendingCreatedAt: now.Add(-2 * time.Minute)},
	}}
	service, err := NewMetrics(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenant := identitydomain.Actor{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"*"}}
	result, err := service.Snapshot(t.Context(), tenant)
	if err != nil || reader.tenantID != tenant.TenantID || reader.includeOutbox || result["outbox_pending_jobs"] != nil || result["object_reconciliation_last_run_age_seconds"] != 60 {
		t.Fatalf("tenant metrics=%#v reader=%#v err=%v", result, reader, err)
	}
	instance := identitydomain.Actor{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"instance:admin"}}
	result, err = service.Snapshot(t.Context(), instance)
	if err != nil || !reader.includeOutbox || result["outbox_pending_jobs"] != 2 || result["outbox_oldest_pending_age_seconds"] != 120 {
		t.Fatalf("instance metrics=%#v reader=%#v err=%v", result, reader, err)
	}
	for _, forbidden := range []string{"payload", "secret", "failure_detail"} {
		if _, exists := result[forbidden]; exists {
			t.Fatalf("metrics exposed %s", forbidden)
		}
	}
}

func TestMetricsRejectsUnexpectedProjectionFields(t *testing.T) {
	reader := &metricsReaderFake{snapshot: MetricsSnapshot{ResourceCounts: map[string]int{"evidence": -1}}}
	service, err := NewMetrics(reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"admin"}}
	if _, err := service.Snapshot(t.Context(), actor); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("invalid projection err=%v", err)
	}
}

func TestMetricsRejectsInconsistentReconciliationTimestamp(t *testing.T) {
	counts := map[string]int{
		"audit_chain_entries": 0, "artifact_signatures": 0, "cosign_verifications": 0,
		"evidence": 0, "merkle_batches": 0, "object_retention_policies": 0,
		"release_bundles": 0, "transparency_checkpoints": 0,
	}
	reader := &metricsReaderFake{snapshot: MetricsSnapshot{
		ResourceCounts: counts, Reconciliation: ReconciliationCounts{Runs: 1},
	}}
	service, err := NewMetrics(reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_a", KeyID: "key_a", Scopes: []string{"admin"}}
	if _, err := service.Snapshot(t.Context(), actor); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("missing reconciliation timestamp err=%v", err)
	}
}
