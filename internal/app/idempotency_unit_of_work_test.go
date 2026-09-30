package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestIdempotencyUnitOfWorkCommitsCommandAndSafeReplay(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	actor := domain.Actor{TenantID: "ten_direct", KeyID: "key_direct"}
	seedIdempotencyTenant(t, memory, actor.TenantID)
	executor := IdempotencyUnitOfWork{Transactions: memory, Now: fixedNow}
	commandRuns := 0
	command := func(ctx context.Context, repositories Repositories) (int, any, error) {
		commandRuns++
		product := domain.Product{ID: "prod_direct", TenantID: actor.TenantID, Name: "Direct", Slug: "direct", CreatedAt: fixedNow()}
		if err := repositories.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
			return 0, nil, err
		}
		if _, err := repositories.Audit.Append(ctx, domain.AuditChainEntry{
			ID: "ace_direct", TenantID: actor.TenantID, EntryType: "product.created",
			SubjectType: "product", SubjectID: product.ID, ActorType: "api_key",
			ActorID: actor.KeyID, OccurredAt: fixedNow(),
		}); err != nil {
			return 0, nil, err
		}
		if err := repositories.Outbox.Enqueue(ctx, OutboxJob{
			ID: "job_direct", TenantID: actor.TenantID, Kind: "index_product",
			SubjectType: "product", SubjectID: product.ID, CreatedAt: fixedNow(),
		}); err != nil {
			return 0, nil, err
		}
		return 201, map[string]any{"id": product.ID, "secret": "one-time-secret"}, nil
	}
	status, response, err := executor.WithBody(ctx, actor, "POST", "/v1/products", "direct-key", []byte(`{"name":"Direct"}`), command)
	if err != nil || status != 201 || response.(map[string]any)["secret"] != "one-time-secret" {
		t.Fatalf("first response status=%d response=%#v err=%v", status, response, err)
	}
	status, response, err = executor.WithBody(ctx, actor, "POST", "/v1/products", "direct-key", []byte(`{"name":"Direct"}`), command)
	if err != nil || status != 201 || commandRuns != 1 {
		t.Fatalf("replay status=%d response=%#v runs=%d err=%v", status, response, commandRuns, err)
	}
	replay := response.(map[string]any)
	if replay["id"] != "prod_direct" || replay["secret"] != nil {
		t.Fatalf("unsafe replay response: %#v", replay)
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/products", "direct-key", []byte(`{"name":"Changed"}`), command); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different request err=%v, want conflict", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil || len(snapshot.Products) != 1 || len(snapshot.Idempotency) != 1 || len(snapshot.AuditEntries[actor.TenantID]) != 1 || len(snapshot.OutboxJobs) != 1 {
		t.Fatalf("atomic state products=%d records=%d audit=%d outbox=%d err=%v", len(snapshot.Products), len(snapshot.Idempotency), len(snapshot.AuditEntries[actor.TenantID]), len(snapshot.OutboxJobs), err)
	}
}

func TestIdempotencyUnitOfWorkBodyDigestConflictsOnChangedBody(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	actor := domain.Actor{TenantID: "ten_direct", KeyID: "key_direct"}
	seedIdempotencyTenant(t, memory, actor.TenantID)
	executor := IdempotencyUnitOfWork{Transactions: memory, Now: fixedNow}
	runs := 0
	command := func(context.Context, Repositories) (int, any, error) {
		runs++
		return 201, map[string]any{"id": "ev_direct"}, nil
	}
	digest := hashBytes([]byte(`{"evidence":"first"}`))
	if _, _, err := executor.WithBodyDigest(ctx, actor, "POST", "/v1/evidence", "digest-key", digest, command); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, _, err := executor.WithBodyDigest(ctx, actor, "POST", "/v1/evidence", "digest-key", digest, command); err != nil || runs != 1 {
		t.Fatalf("replay runs=%d err=%v", runs, err)
	}
	changedDigest := hashBytes([]byte(`{"evidence":"changed"}`))
	if _, _, err := executor.WithBodyDigest(ctx, actor, "POST", "/v1/evidence", "digest-key", changedDigest, command); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed body err=%v, want conflict", err)
	}
}

func TestIdempotencyUnitOfWorkRollsBackFailedCommand(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	actor := domain.Actor{TenantID: "ten_direct", KeyID: "key_direct"}
	seedIdempotencyTenant(t, memory, actor.TenantID)
	executor := IdempotencyUnitOfWork{Transactions: memory, Now: fixedNow}
	commandErr := errors.New("command rejected")
	command := func(ctx context.Context, repositories Repositories) (int, any, error) {
		product := domain.Product{ID: "prod_failed", TenantID: actor.TenantID, Name: "Failed", Slug: "failed", CreatedAt: fixedNow()}
		if err := repositories.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
			return 0, nil, err
		}
		return 409, nil, commandErr
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/products", "failed-key", []byte(`{"name":"Failed"}`), command); !errors.Is(err, commandErr) {
		t.Fatalf("first error=%v, want command error", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil || len(snapshot.Products) != 0 || len(snapshot.Idempotency) != 1 {
		t.Fatalf("rollback state products=%d records=%d err=%v", len(snapshot.Products), len(snapshot.Idempotency), err)
	}
	for _, record := range snapshot.Idempotency {
		if record.State != IdempotencyFailed || record.Response != nil {
			t.Fatalf("failed reservation leaked response: %#v", record)
		}
	}
}

func TestIdempotencyUnitOfWorkScopesKeysByTenantAndActor(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	seedIdempotencyTenant(t, memory, "ten_first")
	seedIdempotencyTenant(t, memory, "ten_second")
	executor := IdempotencyUnitOfWork{Transactions: memory, Now: fixedNow}
	actors := []domain.Actor{
		{TenantID: "ten_first", KeyID: "key_first"},
		{TenantID: "ten_first", KeyID: "key_second"},
		{TenantID: "ten_second", KeyID: "key_first"},
	}
	for i, actor := range actors {
		status, response, err := executor.WithBody(ctx, actor, "POST", "/v1/products", "shared-key", []byte(`{"name":"Shared"}`), func(context.Context, Repositories) (int, any, error) {
			return 201, map[string]any{"actor_index": i}, nil
		})
		if err != nil || status != 201 || response.(map[string]any)["actor_index"] != i {
			t.Fatalf("actor %d status=%d response=%#v err=%v", i, status, response, err)
		}
	}
	snapshot, err := memory.Snapshot()
	if err != nil || len(snapshot.Idempotency) != len(actors) {
		t.Fatalf("scoped record count=%d err=%v", len(snapshot.Idempotency), err)
	}
}

func TestIdempotencyUnitOfWorkCommitFailureLeavesNoProductOrReplay(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	actor := domain.Actor{TenantID: "ten_direct", KeyID: "key_direct"}
	seedIdempotencyTenant(t, memory, actor.TenantID)
	executor := IdempotencyUnitOfWork{Transactions: commitFailingUnitOfWorkFactory{inner: memory}, Now: fixedNow}
	_, _, err := executor.WithBody(ctx, actor, "POST", "/v1/products", "commit-failure", []byte(`{"name":"Failed"}`), func(ctx context.Context, repositories Repositories) (int, any, error) {
		product := domain.Product{ID: "prod_commit_failure", TenantID: actor.TenantID, Name: "Failed", Slug: "failed", CreatedAt: fixedNow()}
		if err := repositories.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
			return 0, nil, err
		}
		return 201, map[string]any{"id": product.ID}, nil
	})
	if err == nil {
		t.Fatal("commit failure must be returned")
	}
	snapshot, err := memory.Snapshot()
	if err != nil || len(snapshot.Products) != 0 || len(snapshot.Idempotency) != 0 {
		t.Fatalf("failed commit products=%d records=%d err=%v", len(snapshot.Products), len(snapshot.Idempotency), err)
	}
}

func TestIdempotencyUnitOfWorkPreparationFailureRemainsRetryable(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	seedIdempotencyTenant(t, memory, "ten_direct")
	executor := IdempotencyUnitOfWork{Transactions: memory, Now: fixedNow}
	reservation, err := newIdempotencyReservation(IdempotencyRecordKey{
		TenantID: "ten_direct", ActorID: "api_key:key_direct", Method: "POST",
		Path: "/v1/products", IdempotencyKey: "prepare-failure",
	}, hashBytes([]byte("prepare-failure")), fixedNow())
	if err != nil {
		t.Fatalf("reservation: %v", err)
	}
	prepareErr := errors.New("temporary preparation failure")
	_, err = executor.withReservation(ctx, reservation, func(context.Context, Repositories) (IdempotentUnitOfWorkCommand, error) {
		return nil, prepareErr
	})
	if !errors.Is(err, prepareErr) {
		t.Fatalf("preparation error=%v, want original", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil || len(snapshot.Idempotency) != 0 {
		t.Fatalf("preparation failure persisted reservation: count=%d err=%v", len(snapshot.Idempotency), err)
	}
}

func seedIdempotencyTenant(t *testing.T, memory *MemoryUnitOfWorkFactory, tenantID string) {
	t.Helper()
	err := ExecuteUnitOfWork(context.Background(), memory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: tenantID, Name: "Direct", CreatedAt: fixedNow()})
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
}
