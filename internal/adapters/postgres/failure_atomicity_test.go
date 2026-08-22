package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// TestPostgresFailureAtomicityRollsBackEveryPreCommitPhase exercises the
// transaction boundary against live PostgreSQL. The injected failures are
// represented only by this test's rollback/cancel actions; production code has
// no environment flag, hook, or request input that can enable them.
func TestPostgresFailureAtomicityRollsBackEveryPreCommitPhase(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_failure_atomic_" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+quotedSchema+" CASCADE") }()

	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	tenantID := "ten_failure_atomic"
	seed, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Repositories().Identity.InsertTenant(ctx, domain.Tenant{ID: tenantID, Name: "Failure atomicity", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	for _, phase := range []struct {
		name         string
		afterDomain  bool
		afterAudit   bool
		afterOutbox  bool
		beforeCommit bool
	}{
		{name: "before_insert"},
		{name: "after_domain_insert", afterDomain: true},
		{name: "after_audit_insert", afterDomain: true, afterAudit: true},
		{name: "after_outbox_insert", afterDomain: true, afterAudit: true, afterOutbox: true},
		{name: "before_commit", afterDomain: true, afterAudit: true, afterOutbox: true, beforeCommit: true},
	} {
		t.Run(phase.name, func(t *testing.T) {
			artifactID := "art_failure_" + phase.name
			auditID := "ace_failure_" + phase.name
			jobID := "job_failure_" + phase.name
			uow, err := store.BeginUnitOfWork(ctx)
			if err != nil {
				t.Fatal(err)
			}
			repositories := uow.Repositories()
			if phase.afterDomain {
				if err := repositories.ReleaseCatalog.InsertArtifact(ctx, domain.Artifact{ID: artifactID, TenantID: tenantID, Name: "failure phase", MediaType: "application/octet-stream", Digest: "sha256:" + strings.Repeat("a", 64), Size: 1, CreatedAt: time.Now().UTC()}); err != nil {
					t.Fatalf("insert artifact: %v", err)
				}
			}
			if phase.afterAudit {
				if _, err := repositories.Audit.Append(ctx, domain.AuditChainEntry{ID: auditID, TenantID: tenantID, EntryType: "failure.atomicity", SubjectType: "artifact", SubjectID: artifactID, ActorType: "system", ActorID: "test", OccurredAt: time.Now().UTC()}); err != nil {
					t.Fatalf("append audit: %v", err)
				}
			}
			if phase.afterOutbox {
				if err := repositories.Outbox.Enqueue(ctx, app.OutboxJob{ID: jobID, TenantID: tenantID, Kind: "index_artifact", SubjectType: "artifact", SubjectID: artifactID, CreatedAt: time.Now().UTC()}); err != nil {
					t.Fatalf("enqueue outbox: %v", err)
				}
			}

			if phase.beforeCommit {
				canceled, cancelCommit := context.WithCancel(ctx)
				cancelCommit()
				if err := uow.Commit(canceled); err == nil {
					t.Fatal("canceled pre-commit context unexpectedly committed")
				}
			}
			if err := uow.Rollback(context.WithoutCancel(ctx)); err != nil {
				t.Fatalf("rollback injected %s failure: %v", phase.name, err)
			}
			assertFailurePhaseInvisible(t, ctx, store, artifactID, auditID, jobID)
		})
	}
}

func assertFailurePhaseInvisible(t *testing.T, ctx context.Context, store *Store, artifactID, auditID, jobID string) {
	t.Helper()
	for _, check := range []struct {
		table string
		id    string
	}{
		{table: "artifacts", id: artifactID},
		{table: "audit_chain_entries", id: auditID},
		{table: "outbox_jobs", id: jobID},
	} {
		var count int
		if err := store.pool.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s WHERE id=$1", check.table), check.id).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", check.table, err)
		}
		if count != 0 {
			t.Fatalf("%s has %d visible rows after an injected pre-commit failure", check.table, count)
		}
	}
}
