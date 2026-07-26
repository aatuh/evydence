package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type failingRetentionPolicyRepository struct{ IntegrityRepository }

func (failingRetentionPolicyRepository) InsertObjectRetentionPolicy(context.Context, domain.ObjectRetentionPolicy) error {
	return errInjectedRepositoryFailure
}

func TestObjectRetentionPolicyUsesUnitOfWorkAndPublishesOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "Retention policy", ObjectKey: "tenants/" + actor.TenantID + "/raw/evidence.json", RequireLegalHold: true, Mode: "governance", RetentionDays: 30})
	if err != nil {
		t.Fatalf("create object retention policy: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got, ok := snapshot.ObjectRetentionPolicies[policy.ID]; !ok || got.TenantID != actor.TenantID || got.ObjectKey != policy.ObjectKey || !got.RequireLegalHold {
		t.Fatalf("object retention policy not committed: %#v", snapshot.ObjectRetentionPolicies)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Integrity.InsertObjectRetentionPolicy(ctx, domain.ObjectRetentionPolicy{})
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid object retention policy err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Integrity.InsertObjectRetentionPolicy(ctx, policy)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate object retention policy err=%v, want conflict", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repositories Repositories) error {
		foreign := policy
		foreign.ID = "retention_foreign_prefix"
		foreign.ObjectPrefix = "tenants/other/"
		foreign.ObjectKey = "tenants/other/raw/evidence.json"
		return repositories.Integrity.InsertObjectRetentionPolicy(ctx, foreign)
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("foreign object retention policy err=%v, want validation", err)
	}
	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Integrity = failingRetentionPolicyRepository{IntegrityRepository: repositories.Integrity}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failure: %v", err)
	}
	if _, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "Failed retention policy", ObjectKey: "tenants/" + actor.TenantID + "/raw/failed.json", Mode: "compliance", RetentionDays: 90}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed object retention policy err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failure: %v", err)
	}
	if len(after.ObjectRetentionPolicies) != len(before.ObjectRetentionPolicies) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || len(ledger.retentionPolicies) != len(before.ObjectRetentionPolicies) {
		t.Fatalf("failed object retention policy published state: before=%#v after=%#v", before, after)
	}
}
