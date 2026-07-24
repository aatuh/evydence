package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestPostgresUnitOfWorkCommitsAndRollsBackFocusedRepositoriesTogether(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_uow_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = admin.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Now().UTC().Round(0)
	uow, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatalf("begin unit of work: %v", err)
	}
	defer func() { _ = uow.Rollback(context.Background()) }()
	repositories := uow.Repositories()
	tenant := domain.Tenant{ID: "ten_uow_a", Name: "Tenant A", CreatedAt: now}
	if err := repositories.Identity.InsertTenant(ctx, tenant); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_uow_b", Name: "Tenant B", CreatedAt: now}); err != nil {
		t.Fatalf("insert tenant B: %v", err)
	}
	product := domain.Product{ID: "prod_uow", TenantID: tenant.ID, Name: "UOW API", Slug: "uow-api", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	entry, err := repositories.Audit.Append(ctx, domain.AuditChainEntry{
		ID:          "ace_uow",
		TenantID:    tenant.ID,
		EntryType:   "product.created",
		SubjectType: "product",
		SubjectID:   product.ID,
		ActorType:   "system",
		ActorID:     "test",
		OccurredAt:  now,
	})
	if err != nil {
		t.Fatalf("append audit: %v", err)
	}
	if entry.Sequence != 1 || entry.EntryHash == "" {
		t.Fatalf("unexpected audit entry: %#v", entry)
	}
	if err := repositories.Outbox.Enqueue(ctx, app.OutboxJob{ID: "job_uow", TenantID: tenant.ID, Kind: "index_product", SubjectType: "product", SubjectID: product.ID, CreatedAt: now}); err != nil {
		t.Fatalf("enqueue outbox: %v", err)
	}
	if err := uow.Commit(ctx); err != nil {
		t.Fatalf("commit unit of work: %v", err)
	}

	for table, want := range map[string]int{"products": 1, "audit_chain_entries": 1, "outbox_jobs": 1} {
		var got int
		if err := store.pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if got != want {
			t.Fatalf("%s count=%d, want %d", table, got, want)
		}
	}

	crossTenant, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatalf("begin cross-tenant unit of work: %v", err)
	}
	defer func() { _ = crossTenant.Rollback(context.Background()) }()
	err = crossTenant.Repositories().ReleaseCatalog.InsertProject(ctx, domain.Project{ID: "proj_cross", TenantID: "ten_uow_b", ProductID: product.ID, Name: "Cross tenant", CreatedAt: now})
	if !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("cross-tenant project err=%v, want not found", err)
	}
	if err := crossTenant.Rollback(ctx); err != nil {
		t.Fatalf("rollback cross-tenant unit of work: %v", err)
	}

	rollback, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatalf("begin rollback unit of work: %v", err)
	}
	defer func() { _ = rollback.Rollback(context.Background()) }()
	rollbackRepositories := rollback.Repositories()
	if err := rollbackRepositories.ReleaseCatalog.InsertArtifact(ctx, domain.Artifact{ID: "art_rollback", TenantID: tenant.ID, Name: "Rollback", MediaType: "application/octet-stream", Digest: "sha256:rollback", Size: 1, CreatedAt: now}); err != nil {
		t.Fatalf("insert rollback artifact: %v", err)
	}
	if _, err := rollbackRepositories.Audit.Append(ctx, domain.AuditChainEntry{ID: "ace_rollback", TenantID: tenant.ID, EntryType: "artifact.created", SubjectType: "artifact", SubjectID: "art_rollback", ActorType: "system", ActorID: "test", OccurredAt: now}); err != nil {
		t.Fatalf("append rollback audit: %v", err)
	}
	if err := rollbackRepositories.Outbox.Enqueue(ctx, app.OutboxJob{ID: "job_rollback", TenantID: tenant.ID, Kind: "index_artifact", SubjectType: "artifact", SubjectID: "art_rollback", CreatedAt: now}); err != nil {
		t.Fatalf("enqueue rollback outbox: %v", err)
	}
	if err := rollback.Rollback(ctx); err != nil {
		t.Fatalf("rollback unit of work: %v", err)
	}
	for table, want := range map[string]int{"artifacts": 0, "audit_chain_entries": 1, "outbox_jobs": 1} {
		var got int
		if err := store.pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&got); err != nil {
			t.Fatalf("count %s after rollback: %v", table, err)
		}
		if got != want {
			t.Fatalf("%s count after rollback=%d, want %d", table, got, want)
		}
	}
}
