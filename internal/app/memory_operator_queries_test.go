package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func TestMemoryOperatorQueriesReadOnlyScalarCurrentRepositoryState(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	metrics, ok := tx.Repositories().Enterprise.(operationsquery.MetricsReader)
	if !ok {
		t.Fatal("memory operations lacks focused scalar metrics reader")
	}
	instance, ok := tx.Repositories().Enterprise.(operationsquery.InstanceCountsReader)
	if !ok {
		t.Fatal("memory operations lacks focused instance count reader")
	}
	// Only ownership/count fields are selected. Even selected rows may have
	// private or malformed metadata that must not be parsed, copied or exposed.
	private := strings.Repeat("private", 10000)
	tx.state.Users = map[string]domain.HumanUser{}
	tx.state.Collectors = map[string]domain.Collector{}
	tx.state.Users["owner"] = domain.HumanUser{ID: "owner", TenantID: "tenant", Email: private}
	tx.state.Users["foreign"] = domain.HumanUser{ID: "foreign", TenantID: "foreign", Email: private}
	tx.state.Collectors["collector"] = domain.Collector{ID: "collector", TenantID: "foreign"}
	tx.state.Evidence["owner"] = domain.EvidenceItem{ID: "owner", TenantID: "tenant", Title: private}
	tx.state.Evidence["foreign"] = domain.EvidenceItem{ID: "foreign", TenantID: "foreign", Title: private}
	tx.state.ArtifactSignatures["owner"] = domain.ArtifactSignature{TenantID: "tenant"}
	tx.state.ArtifactSignatures["foreign"] = domain.ArtifactSignature{TenantID: "foreign"}
	tx.state.CosignVerifications["owner"] = domain.CosignVerification{TenantID: "tenant"}
	tx.state.CosignVerifications["foreign"] = domain.CosignVerification{TenantID: "foreign"}
	tx.state.MerkleBatches["owner"] = domain.MerkleBatch{TenantID: "tenant"}
	tx.state.MerkleBatches["foreign"] = domain.MerkleBatch{TenantID: "foreign"}
	tx.state.ObjectRetentionPolicies["owner"] = domain.ObjectRetentionPolicy{TenantID: "tenant"}
	tx.state.ObjectRetentionPolicies["foreign"] = domain.ObjectRetentionPolicy{TenantID: "foreign"}
	tx.state.ReleaseBundles["owner"] = domain.ReleaseBundle{TenantID: "tenant"}
	tx.state.ReleaseBundles["foreign"] = domain.ReleaseBundle{TenantID: "foreign"}
	tx.state.TransparencyCheckpoints["owner"] = domain.TransparencyCheckpoint{TenantID: "tenant"}
	tx.state.TransparencyCheckpoints["foreign"] = domain.TransparencyCheckpoint{TenantID: "foreign"}
	tx.state.AuditEntries["tenant"] = []domain.AuditChainEntry{{TenantID: "tenant"}, {TenantID: "tenant"}}
	tx.state.AuditEntries["foreign"] = []domain.AuditChainEntry{{TenantID: "foreign"}}
	at := fixedNow()
	tx.state.CustomerPortalAccess["owner"] = domain.CustomerPortalAccess{TenantID: "tenant", FailedAccessCount: 3, RevokedAt: &at}
	tx.state.CustomerPortalAccess["foreign"] = domain.CustomerPortalAccess{TenantID: "foreign", FailedAccessCount: -1}
	tx.state.OutboxJobs["owner"] = OutboxJob{ID: "owner", TenantID: "tenant", CreatedAt: at, Payload: map[string]any{"private": private}}
	tx.state.OutboxJobs["foreign"] = OutboxJob{ID: "foreign", TenantID: "foreign", CreatedAt: at.Add(-1), Payload: map[string]any{"private": private}}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	want := operationsquery.MetricsSnapshot{ResourceCounts: map[string]int{
		"audit_chain_entries": 2, "artifact_signatures": 1, "cosign_verifications": 1,
		"evidence": 1, "merkle_batches": 1, "object_retention_policies": 1,
		"release_bundles": 1, "transparency_checkpoints": 1,
	}, CustomerPortalFailedAccessCount: 3, CustomerPortalRevokedAccessCount: 1}
	got, err := metrics.ReadMetricsSnapshot(t.Context(), "tenant", false)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("tenant scalar snapshot selected private/foreign state or lost counts", got, err)
	}
	got.ResourceCounts["evidence"] = -1
	want.Outbox = &operationsquery.OutboxCounts{PendingJobs: 2, OldestPendingCreatedAt: at.Add(-1)}
	got, err = metrics.ReadMetricsSnapshot(t.Context(), "tenant", true)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("operator snapshot lost detached counts or global queued-job scalar projection", got, err)
	}
	counts, err := instance.ReadInstanceCounts(t.Context())
	if err != nil || counts != (operationsquery.InstanceCounts{Tenants: len(tx.state.Tenants), Users: 2, Collectors: 1, Evidence: 2}) {
		t.Fatal("instance read lost global cardinalities", counts, err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("scalar queries changed any repository state")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := metrics.ReadMetricsSnapshot(ctx, "tenant", true); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, operationsquery.MetricsSnapshot{}) {
		t.Fatal("cancelled metrics returned a partial snapshot", v, err)
	}
	if v, err := instance.ReadInstanceCounts(ctx); !errors.Is(err, context.Canceled) || v != (operationsquery.InstanceCounts{}) {
		t.Fatal("cancelled instance read returned counts", v, err)
	}
	if _, err := metrics.ReadMetricsSnapshot(t.Context(), "unknown", false); !errors.Is(err, ErrNotFound) {
		t.Fatal("metrics did not check current tenant", err)
	}
	var missingContext context.Context
	if _, err := metrics.ReadMetricsSnapshot(missingContext, "tenant", false); !errors.Is(err, ErrValidation) {
		t.Fatal("metrics accepted missing context", err)
	}
	if _, err := instance.ReadInstanceCounts(missingContext); !errors.Is(err, ErrValidation) {
		t.Fatal("instance read accepted missing context", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := metrics.ReadMetricsSnapshot(t.Context(), "tenant", true); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction returned metrics", err)
	}
	if _, err := instance.ReadInstanceCounts(t.Context()); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction returned instance counts", err)
	}
}

func TestMemoryOperatorQueriesRejectCorruptSelectedCountersWithoutPartialResults(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Enterprise.(operationsquery.MetricsReader)
	if !ok {
		t.Fatal("missing focused metrics reader")
	}
	maxInt := int(^uint(0) >> 1)
	for name, failures := range map[string][]int{"negative": {-1}, "overflow": {maxInt, 1}} {
		t.Run(name, func(t *testing.T) {
			tx.state.CustomerPortalAccess = map[string]domain.CustomerPortalAccess{}
			for i, n := range failures {
				tx.state.CustomerPortalAccess[string(rune('a'+i))] = domain.CustomerPortalAccess{TenantID: "tenant", FailedAccessCount: n}
			}
			if v, err := r.ReadMetricsSnapshot(t.Context(), "tenant", false); !errors.Is(err, operationsquery.ErrInvalidProjection) || !reflect.DeepEqual(v, operationsquery.MetricsSnapshot{}) {
				t.Fatal("corrupt selected counter returned a partial result", v, err)
			}
		})
	}
}
