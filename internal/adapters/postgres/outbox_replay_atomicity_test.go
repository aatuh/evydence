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

func TestOutboxReplayAndIdempotencyCommitOrRollbackTogether(t *testing.T) {
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
	schema := "evydence_outbox_replay_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
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
		t.Fatal(err)
	}
	now := time.Now().UTC().Round(0)
	seed, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Repositories().Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_replay_atomicity", Name: "Replay atomicity", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	job := app.OutboxJob{ID: "job_replay_atomicity", TenantID: "ten_replay_atomicity", Kind: "parse_sbom", SubjectType: "sbom", SubjectID: "sbom_replay_atomicity", Payload: map[string]any{"payload_hash": "sha256:abc", "parser_version": "cyclonedx-json.v1.0.0"}, CreatedAt: now}
	if err := store.Enqueue(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET status = 'dead_letter', terminal_at = now() WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}

	actor := domain.Actor{TenantID: job.TenantID, KeyID: "key_instance_operator", Scopes: []string{app.ScopeInstanceAdmin}}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	path := "/v1/admin/outbox/" + job.ID + "/replay"
	injected := errors.New("injected command failure")
	if _, _, err := executor.WithBody(ctx, actor, "POST", path, "replay-rollback", []byte("{}"), func(ctx context.Context, repositories app.Repositories) (int, any, error) {
		if _, err := repositories.OutboxReplay.ReplayTerminalJob(ctx, job.ID, actor.KeyID); err != nil {
			return 0, nil, err
		}
		return 0, nil, injected
	}); !errors.Is(err, injected) {
		t.Fatalf("rollback replay err=%v", err)
	}
	assertReplayState := func(wantStatus string, wantAttempts, wantAudit int) {
		t.Helper()
		var status string
		var attempts, audit int
		if err := store.pool.QueryRow(ctx, `SELECT status FROM outbox_jobs WHERE id = $1`, job.ID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_job_attempts WHERE job_id = $1`, job.ID).Scan(&attempts); err != nil {
			t.Fatal(err)
		}
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries WHERE tenant_id = $1 AND entry_type = 'outbox_job.replayed'`, job.TenantID).Scan(&audit); err != nil {
			t.Fatal(err)
		}
		if status != wantStatus || attempts != wantAttempts || audit != wantAudit {
			t.Fatalf("status=%q attempts=%d audit=%d, want %q/%d/%d", status, attempts, audit, wantStatus, wantAttempts, wantAudit)
		}
	}
	assertReplayState("dead_letter", 0, 0)
	var completed int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE state = 'completed'`).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if completed != 0 {
		t.Fatalf("rolled-back replay completed %d idempotency records", completed)
	}

	runCount := 0
	run := func(ctx context.Context, repositories app.Repositories) (int, any, error) {
		runCount++
		replay, err := repositories.OutboxReplay.ReplayTerminalJob(ctx, job.ID, actor.KeyID)
		return 200, replay, err
	}
	status, first, err := executor.WithBody(ctx, actor, "POST", path, "replay-success", []byte("{}"), run)
	if err != nil || status != 200 {
		t.Fatalf("replay status=%d response=%#v err=%v", status, first, err)
	}
	status, second, err := executor.WithBody(ctx, actor, "POST", path, "replay-success", []byte("{}"), run)
	if err != nil || status != 200 || runCount != 1 {
		t.Fatalf("idempotent replay status=%d response=%#v runs=%d err=%v", status, second, runCount, err)
	}
	assertReplayState("queued", 1, 1)
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE state = 'completed'`).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if completed != 1 {
		t.Fatalf("successful replay completed %d idempotency records", completed)
	}
}
