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

func TestOutboxDeduplicatesReclaimsDeadLettersAndAuditsReplay(t *testing.T) {
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
	schema := "evydence_outbox_lifecycle_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
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
	if err := seed.Repositories().Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_outbox_lifecycle", Name: "Outbox lifecycle", CreatedAt: now}); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatalf("commit tenant: %v", err)
	}
	job := app.OutboxJob{ID: "job_outbox_lifecycle", TenantID: "ten_outbox_lifecycle", Kind: "parse_sbom", SubjectType: "sbom", SubjectID: "sbom_lifecycle", Payload: map[string]any{"payload_hash": "sha256:abc", "parser_version": "cyclonedx-json.v1.0.0"}, CreatedAt: now}
	if err := store.Enqueue(ctx, job); err != nil {
		t.Fatalf("enqueue job: %v", err)
	}
	duplicate := job
	duplicate.ID = "job_outbox_lifecycle_duplicate"
	if err := store.Enqueue(ctx, duplicate); err != nil {
		t.Fatalf("enqueue duplicate: %v", err)
	}
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_jobs WHERE tenant_id = 'ten_outbox_lifecycle'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("deduplicated jobs=%d, want 1", count)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET max_attempts = 2 WHERE id = 'job_outbox_lifecycle'`); err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(first) != 1 || first[0].LeaseToken == "" || first[0].Attempts != 1 {
		t.Fatalf("first claim=%#v err=%v", first, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET locked_at = now() - interval '6 minutes' WHERE id = 'job_outbox_lifecycle'`); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].Attempts != 2 || reclaimed[0].LeaseToken == first[0].LeaseToken {
		t.Fatalf("reclaimed=%#v err=%v", reclaimed, err)
	}
	if err := store.CompleteJob(ctx, first[0].ID, first[0].LeaseToken); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale completion err=%v, want conflict", err)
	}
	if err := store.FailJob(ctx, reclaimed[0].ID, reclaimed[0].LeaseToken, JobFailure{Class: JobFailurePermanent, Code: "unsupported_operation"}); err != nil {
		t.Fatalf("dead-letter job: %v", err)
	}
	var status, failureClass, failureCode string
	var terminalAt *time.Time
	if err := store.pool.QueryRow(ctx, `SELECT status, failure_class, failure_code, terminal_at FROM outbox_jobs WHERE id = 'job_outbox_lifecycle'`).Scan(&status, &failureClass, &failureCode, &terminalAt); err != nil {
		t.Fatal(err)
	}
	if status != "dead_letter" || failureClass != "permanent" || failureCode != "unsupported_operation" || terminalAt == nil {
		t.Fatalf("terminal job status=%q class=%q code=%q terminal=%v", status, failureClass, failureCode, terminalAt)
	}
	if jobs, err := store.ClaimJobs(ctx, 1); err != nil || len(jobs) != 0 {
		t.Fatalf("terminal job claim=%#v err=%v, want no retry", jobs, err)
	}
	replay, err := store.ReplayTerminalJob(ctx, job.ID, "key_instance_operator")
	if err != nil || replay.JobID != job.ID || replay.Status != "queued" || replay.ReplayedAt.IsZero() {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT status, attempts FROM outbox_jobs WHERE id = 'job_outbox_lifecycle'`).Scan(&status, &count); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || count != 0 {
		t.Fatalf("replayed job status=%q attempts=%d, want queued/0", status, count)
	}
	replayed, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(replayed) != 1 || replayed[0].ID != job.ID {
		t.Fatalf("claim replayed job=%#v err=%v", replayed, err)
	}
	if err := store.CompleteJob(ctx, replayed[0].ID, replayed[0].LeaseToken); err != nil {
		t.Fatalf("complete replayed job: %v", err)
	}

	transient := job
	transient.ID = "job_outbox_transient"
	transient.SubjectID = "sbom_transient"
	transient.Payload = map[string]any{"payload_hash": "sha256:transient", "parser_version": "cyclonedx-json.v1.0.0"}
	if err := store.Enqueue(ctx, transient); err != nil {
		t.Fatalf("enqueue transient job: %v", err)
	}
	transientClaims, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(transientClaims) != 1 || transientClaims[0].ID != transient.ID {
		t.Fatalf("claim transient job=%#v err=%v", transientClaims, err)
	}
	if err := store.FailJob(ctx, transientClaims[0].ID, transientClaims[0].LeaseToken, JobFailure{Class: JobFailureTransient, Code: "worker_interrupted"}); err != nil {
		t.Fatalf("retry transient job: %v", err)
	}
	var retryDelaySeconds float64
	if err := store.pool.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM run_after - now()) FROM outbox_jobs WHERE id = 'job_outbox_transient' AND status = 'retrying'`).Scan(&retryDelaySeconds); err != nil {
		t.Fatalf("load transient retry delay: %v", err)
	}
	if retryDelaySeconds < 1 || retryDelaySeconds > 300 {
		t.Fatalf("transient retry delay=%f, want bounded exponential delay with jitter", retryDelaySeconds)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET run_after = now() - interval '1 second' WHERE id = 'job_outbox_transient'`); err != nil {
		t.Fatal(err)
	}
	poisonedClaims, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(poisonedClaims) != 1 || poisonedClaims[0].ID != transient.ID {
		t.Fatalf("claim transient retry=%#v err=%v", poisonedClaims, err)
	}
	if err := store.FailJob(ctx, poisonedClaims[0].ID, poisonedClaims[0].LeaseToken, JobFailure{Class: JobFailurePoisoned, Code: "payload_invariant_failed"}); err != nil {
		t.Fatalf("dead-letter poisoned job: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT status, failure_class, failure_code FROM outbox_jobs WHERE id = 'job_outbox_transient'`).Scan(&status, &failureClass, &failureCode); err != nil {
		t.Fatal(err)
	}
	if status != "dead_letter" || failureClass != "poisoned" || failureCode != "payload_invariant_failed" {
		t.Fatalf("poisoned job status=%q class=%q code=%q", status, failureClass, failureCode)
	}
	var auditCount, attemptCount int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries WHERE tenant_id = 'ten_outbox_lifecycle' AND entry_type = 'outbox_job.replayed'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_job_attempts WHERE job_id = 'job_outbox_lifecycle'`).Scan(&attemptCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || attemptCount < 4 {
		t.Fatalf("replay audit=%d attempts=%d, want 1 and at least 4", auditCount, attemptCount)
	}
	diagnostics, err := store.OutboxDiagnostics(ctx)
	if err != nil || diagnostics.PendingJobs != 0 || diagnostics.TerminalJobs != 1 || !diagnostics.OldestPendingCreatedAt.IsZero() {
		t.Fatalf("diagnostics=%#v err=%v", diagnostics, err)
	}
}
