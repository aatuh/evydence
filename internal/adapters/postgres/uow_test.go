package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestPostgresAuditRepositoryAllocatesStrictConcurrentSequences(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_audit_repository_sequence_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.pool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") }()
	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Now().UTC().Round(0)
	seed, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Repositories().Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_audit_sequence", Name: "Audit sequence", CreatedAt: now}); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatalf("commit tenant: %v", err)
	}

	const writers = 16
	ready := make(chan struct{}, writers)
	start := make(chan struct{})
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		i := i
		go func() {
			ready <- struct{}{}
			<-start
			uow, err := store.BeginUnitOfWork(ctx)
			if err != nil {
				errs <- err
				return
			}
			_, err = uow.Repositories().Audit.Append(ctx, domain.AuditChainEntry{
				ID:          fmt.Sprintf("ace_audit_sequence_%02d", i),
				TenantID:    "ten_audit_sequence",
				EntryType:   "test.concurrent",
				SubjectType: "test",
				SubjectID:   fmt.Sprintf("subject-%02d", i),
				ActorType:   "system",
				ActorID:     "test",
				OccurredAt:  now,
			})
			if err == nil {
				err = uow.Commit(ctx)
			} else {
				_ = uow.Rollback(ctx)
			}
			errs <- err
		}()
	}
	for range writers {
		<-ready
	}
	close(start)
	for range writers {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent audit append: %v", err)
		}
	}
	rows, err := store.pool.Query(ctx, `SELECT sequence, previous_entry_hash, entry_hash FROM audit_chain_entries WHERE tenant_id = 'ten_audit_sequence' ORDER BY sequence`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	previous := ""
	count := 0
	for rows.Next() {
		var sequence int64
		var previousHash, entryHash string
		if err := rows.Scan(&sequence, &previousHash, &entryHash); err != nil {
			t.Fatal(err)
		}
		if sequence != int64(count+1) || previousHash != previous || entryHash == "" {
			t.Fatalf("audit sequence %d has previous=%q entry=%q, want contiguous chain after %q", sequence, previousHash, entryHash, previous)
		}
		previous = entryHash
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != writers {
		t.Fatalf("audit entries=%d, want %d", count, writers)
	}
	var nextSequence int64
	if err := store.pool.QueryRow(ctx, `SELECT next_sequence FROM tenant_audit_sequences WHERE tenant_id = 'ten_audit_sequence'`).Scan(&nextSequence); err != nil {
		t.Fatal(err)
	}
	if nextSequence != writers+1 {
		t.Fatalf("next sequence=%d, want %d", nextSequence, writers+1)
	}
}

func TestPostgresReleaseRepositoryRejectsStaleConcurrentRevision(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_release_revision_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.pool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") }()
	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Now().UTC().Round(0)
	seed, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repositories := seed.Repositories()
	tenant := domain.Tenant{ID: "ten_release_revision", Name: "Release revision", CreatedAt: now}
	product := domain.Product{ID: "prod_release_revision", TenantID: tenant.ID, Name: "Revision product", Slug: "revision-product", CreatedAt: now}
	release := domain.Release{ID: "rel_release_revision", TenantID: tenant.ID, ProductID: product.ID, Version: "1.0.0", Revision: 1, State: "draft", CreatedAt: now}
	if err := repositories.Identity.InsertTenant(ctx, tenant); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := repositories.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	if err := repositories.ReleaseCatalog.InsertRelease(ctx, release); err != nil {
		t.Fatalf("insert release: %v", err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	const writers = 8
	ready := make(chan struct{}, writers)
	start := make(chan struct{})
	errs := make(chan error, writers)
	for range writers {
		go func() {
			ready <- struct{}{}
			<-start
			uow, err := store.BeginUnitOfWork(ctx)
			if err != nil {
				errs <- err
				return
			}
			frozenAt := now
			update := release
			update.State = "frozen"
			update.Revision = 2
			update.FrozenAt = &frozenAt
			err = uow.Repositories().ReleaseCatalog.UpdateReleaseState(ctx, update, "draft")
			if err == nil {
				err = uow.Commit(ctx)
			} else {
				_ = uow.Rollback(ctx)
			}
			errs <- err
		}()
	}
	for range writers {
		<-ready
	}
	close(start)
	successes := 0
	for range writers {
		err := <-errs
		if err == nil {
			successes++
			continue
		}
		if revision, ok := app.CurrentRevision(err); !ok || revision != 2 {
			t.Fatalf("stale release update err=%v, want current revision 2", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful release updates=%d, want one", successes)
	}
	var state string
	var revision int64
	if err := store.pool.QueryRow(ctx, `SELECT state, revision FROM releases WHERE id = 'rel_release_revision'`).Scan(&state, &revision); err != nil {
		t.Fatal(err)
	}
	if state != "frozen" || revision != 2 {
		t.Fatalf("stored release state=%q revision=%d, want frozen/2", state, revision)
	}
}

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
