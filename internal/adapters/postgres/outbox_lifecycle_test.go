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
	active, err := store.HasActiveJobDependency(ctx, job.TenantID, job.Kind, job.SubjectType, job.SubjectID)
	if err != nil || !active {
		t.Fatalf("queued dependency active=%v err=%v, want active", active, err)
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
	active, err = store.HasActiveJobDependency(ctx, job.TenantID, job.Kind, job.SubjectType, job.SubjectID)
	if err != nil || active {
		t.Fatalf("dead-letter dependency active=%v err=%v, want terminal", active, err)
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
	active, err = store.HasActiveJobDependency(ctx, job.TenantID, job.Kind, job.SubjectType, job.SubjectID)
	if err != nil || !active {
		t.Fatalf("replayed dependency active=%v err=%v, want active", active, err)
	}
	replayed, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(replayed) != 1 || replayed[0].ID != job.ID {
		t.Fatalf("claim replayed job=%#v err=%v", replayed, err)
	}
	if err := store.CompleteJob(ctx, replayed[0].ID, replayed[0].LeaseToken); err != nil {
		t.Fatalf("complete replayed job: %v", err)
	}
	active, err = store.HasActiveJobDependency(ctx, job.TenantID, job.Kind, job.SubjectType, job.SubjectID)
	if err != nil || active {
		t.Fatalf("succeeded dependency active=%v err=%v, want inactive", active, err)
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

func TestDeferJobPreservesRetryBudgetAndFencesLease(t *testing.T) {
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
	schema := "evydence_outbox_defer_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
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
	tenantID := "ten_outbox_defer"
	if err := store.ApplyCriticalMutation(ctx, app.CriticalMutation{Tenants: []domain.Tenant{{ID: tenantID, Name: "Outbox defer", CreatedAt: now}}}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	job := app.OutboxJob{
		ID: "job_outbox_defer", TenantID: tenantID, Kind: "parse_vex", SubjectType: "vex_document", SubjectID: "vex_defer",
		Payload: map[string]any{"payload_hash": "sha256:" + strings.Repeat("a", 64), "parser_version": app.ParserVersionOpenVEXJSON}, CreatedAt: now,
	}
	if err := store.Enqueue(ctx, job); err != nil {
		t.Fatalf("enqueue job: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET max_attempts = 1 WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(claimed) != 1 || claimed[0].Attempts != 1 {
		t.Fatalf("claim job=%#v err=%v", claimed, err)
	}
	dependencyPending := JobFailure{Class: JobFailureTransient, Code: "dependency_pending"}
	if err := store.DeferJob(ctx, claimed[0].ID, "stale_lease", dependencyPending); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale deferral err=%v, want conflict", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET locked_at = now() - interval '6 minutes' WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeferJob(ctx, claimed[0].ID, claimed[0].LeaseToken, dependencyPending); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("expired lease deferral err=%v, want conflict", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET locked_at = now() WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeferJob(ctx, claimed[0].ID, claimed[0].LeaseToken, JobFailure{Class: JobFailureTransient, Code: "worker_interrupted"}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("ordinary failure deferral err=%v, want validation", err)
	}
	if err := store.DeferJob(ctx, claimed[0].ID, claimed[0].LeaseToken, dependencyPending); err != nil {
		t.Fatalf("defer dependency-pending job: %v", err)
	}

	var status, leaseToken, failureClass, failureCode string
	var attempts int
	var retryDelaySeconds float64
	var terminalAt *time.Time
	if err := store.pool.QueryRow(ctx, `
		SELECT status, attempts, COALESCE(lease_token, ''), failure_class, failure_code, terminal_at,
		       EXTRACT(EPOCH FROM run_after - now())
		FROM outbox_jobs WHERE id = $1
	`, job.ID).Scan(&status, &attempts, &leaseToken, &failureClass, &failureCode, &terminalAt, &retryDelaySeconds); err != nil {
		t.Fatal(err)
	}
	if status != "retrying" || attempts != 0 || leaseToken != "" || failureClass != "transient" || failureCode != "dependency_pending" || terminalAt != nil || retryDelaySeconds <= 0 || retryDelaySeconds > outboxDependencyDeferralDelay.Seconds() {
		t.Fatalf("deferred job status=%q attempts=%d lease=%q class=%q code=%q terminal=%v delay=%f", status, attempts, leaseToken, failureClass, failureCode, terminalAt, retryDelaySeconds)
	}
	var recordedAttempt int
	var outcome string
	if err := store.pool.QueryRow(ctx, `
		SELECT attempt, outcome FROM outbox_job_attempts
		WHERE job_id = $1 AND failure_code = 'dependency_pending'
		ORDER BY id DESC LIMIT 1
	`, job.ID).Scan(&recordedAttempt, &outcome); err != nil {
		t.Fatal(err)
	}
	if recordedAttempt != 1 || outcome != "deferred" {
		t.Fatalf("deferral history attempt=%d outcome=%q, want 1/deferred", recordedAttempt, outcome)
	}
	if err := store.DeferJob(ctx, claimed[0].ID, claimed[0].LeaseToken, dependencyPending); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("released lease deferral err=%v, want conflict", err)
	}

	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET run_after = now() - interval '1 second' WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].Attempts != 1 || reclaimed[0].LeaseToken == claimed[0].LeaseToken {
		t.Fatalf("reclaim deferred job=%#v err=%v", reclaimed, err)
	}
	if err := store.FailJob(ctx, reclaimed[0].ID, reclaimed[0].LeaseToken, JobFailure{Class: JobFailureTransient, Code: "worker_interrupted"}); err != nil {
		t.Fatalf("exhaust ordinary retry budget: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT status, attempts, terminal_at FROM outbox_jobs WHERE id = $1`, job.ID).Scan(&status, &attempts, &terminalAt); err != nil {
		t.Fatal(err)
	}
	if status != "dead_letter" || attempts != 1 || terminalAt == nil {
		t.Fatalf("ordinary failure status=%q attempts=%d terminal=%v, want dead_letter/1/non-nil", status, attempts, terminalAt)
	}
}

func TestClaimedReleaseLedgerMutationFencesReclaimedWorker(t *testing.T) {
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
	schema := "evydence_outbox_fencing_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
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
	tenantID := "ten_outbox_fencing"
	if err := store.ApplyCriticalMutation(ctx, app.CriticalMutation{Tenants: []domain.Tenant{{ID: tenantID, Name: "Outbox fencing", CreatedAt: now}}}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	hash := "sha256:" + strings.Repeat("a", 64)
	evidence := domain.EvidenceItem{
		ID: "ev_outbox_fencing", TenantID: tenantID, Type: "vex", Title: "VEX", SourceSystem: "api", ObservedAt: now,
		SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadHash: hash, CanonicalHash: hash,
		Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "L2", VerificationStatus: "pending", CreatedAt: now,
	}
	vex := domain.VEXDocument{
		ID: "vex_outbox_fencing", TenantID: tenantID, EvidenceID: evidence.ID, Format: "openvex", Author: "security",
		SchemaVersion: domain.VEXDocumentSchemaVersion, CreatedAt: now,
	}
	report := domain.VEXImportReport{
		ID: "vex_report_outbox_fencing", TenantID: tenantID, VEXDocumentID: vex.ID, EvidenceID: evidence.ID,
		ParserVersion: app.ParserVersionOpenVEXJSON, Status: "accepted", SchemaVersion: domain.VEXImportReportSchemaVersion,
		CreatedAt: now, UpdatedAt: now,
	}
	job := app.OutboxJob{
		ID: "job_outbox_fencing", TenantID: tenantID, Kind: "parse_vex", SubjectType: "vex", SubjectID: vex.ID,
		Payload: map[string]any{"payload_hash": hash, "parser_version": app.ParserVersionOpenVEXJSON}, CreatedAt: now,
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, app.ReleaseLedgerMutation{
		Evidence: []domain.EvidenceItem{evidence}, VEXDocuments: []domain.VEXDocument{vex},
		VEXImportReports: []domain.VEXImportReport{report}, OutboxJobs: []app.OutboxJob{job},
	}); err != nil {
		t.Fatalf("seed parser state: %v", err)
	}
	first, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim=%#v err=%v", first, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET locked_at = now() - interval '6 minutes' WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}
	successor, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(successor) != 1 || successor[0].LeaseToken == first[0].LeaseToken {
		t.Fatalf("successor claim=%#v err=%v", successor, err)
	}

	parsed := report
	parsed.Status = "parsed"
	parsed.DecisionsCreated = 1
	parsed.UpdatedAt = now.Add(time.Minute)
	if err := store.ApplyClaimedReleaseLedgerMutation(ctx, successor[0].ID, successor[0].LeaseToken, app.ReleaseLedgerMutation{VEXImportReports: []domain.VEXImportReport{parsed}}); err != nil {
		t.Fatalf("persist successor result: %v", err)
	}
	failed := report
	failed.Status = "failed"
	failed.FailureCode = "parser_failed"
	failed.FailureDetail = "Parser processing failed."
	failed.UpdatedAt = now.Add(2 * time.Minute)
	if err := store.ApplyClaimedReleaseLedgerMutation(ctx, first[0].ID, first[0].LeaseToken, app.ReleaseLedgerMutation{VEXImportReports: []domain.VEXImportReport{failed}}); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale worker mutation err=%v, want conflict", err)
	}
	if err := store.CompleteJob(ctx, successor[0].ID, successor[0].LeaseToken); err != nil {
		t.Fatalf("complete successor: %v", err)
	}
	var status, failureCode string
	var decisionsCreated int
	if err := store.pool.QueryRow(ctx, `SELECT status, decisions_created, failure_code FROM vex_import_reports WHERE id = $1`, report.ID).Scan(&status, &decisionsCreated, &failureCode); err != nil {
		t.Fatalf("load final report: %v", err)
	}
	if status != "parsed" || decisionsCreated != 1 || failureCode != "" {
		t.Fatalf("final report status=%q decisions=%d failure=%q, want successor result", status, decisionsCreated, failureCode)
	}
}
