package wiring

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func TestPostgresOutboxReplayCommandAuthorizesAndReplaysAtomicallyWithoutLedger(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("evydence_outbox_replay_command_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}()
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	runtime, err := OpenRuntime(ctx, RuntimeConfig{
		Process: API, Profile: PostgreSQL, DatabaseURL: parsed.String(), LoadMode: "relational_only",
		MigrationsDir: "../../../migrations", ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	scoped, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer scoped.Close()
	now := time.Now().UTC()
	if err := app.ExecuteUnitOfWork(ctx, runtime.Postgres, func(ctx context.Context, repositories app.Repositories) error {
		return repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_replay_command", Name: "Replay command", CreatedAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	job := app.OutboxJob{ID: "job_replay_command", TenantID: "ten_replay_command", Kind: "parse_sbom", SubjectType: "sbom", SubjectID: "sbom_replay_command", Payload: map[string]any{"payload_hash": "sha256:abc", "parser_version": "cyclonedx-json.v1.0.0"}, CreatedAt: now}
	if err := runtime.Postgres.Enqueue(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, err := scoped.Exec(ctx, `UPDATE outbox_jobs SET status = 'dead_letter', terminal_at = now() WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}
	command, err := BuildOutboxReplayCommand(runtime.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/admin/outbox/" + job.ID + "/replay"
	operator := domain.Actor{TenantID: job.TenantID, KeyID: "key_operator", Scopes: []string{app.ScopeInstanceAdmin}}
	wildcard := domain.Actor{TenantID: job.TenantID, KeyID: operator.KeyID, Scopes: []string{"*"}}
	if _, _, err := command.ReplayIdempotent(ctx, wildcard, "POST", path, "same-key", []byte("{}"), job.ID); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("wildcard replay err=%v, want forbidden", err)
	}
	if _, _, err := command.ReplayIdempotent(ctx, operator, "POST", path, "", []byte("{}"), job.ID); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("missing idempotency key err=%v, want validation", err)
	}
	service, err := operationsapp.NewOutboxReplayCommands(outboxReplayTransactions{factory: runtime.Postgres})
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected response failure")
	executor := app.IdempotencyUnitOfWork{Transactions: runtime.Postgres}
	if _, _, err := executor.WithBody(ctx, operator, "POST", path, "rollback-key", []byte("{}"), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		if _, err := service.ReplayTerminalJob(ctx, operator, job.ID); err != nil {
			return 0, nil, err
		}
		return 0, nil, injected
	}); !errors.Is(err, injected) {
		t.Fatalf("nested replay rollback err=%v", err)
	}
	var beforeStatus string
	var beforeAttempts int
	if err := scoped.QueryRow(ctx, `SELECT status FROM outbox_jobs WHERE id = $1`, job.ID).Scan(&beforeStatus); err != nil {
		t.Fatal(err)
	}
	if err := scoped.QueryRow(ctx, `SELECT count(*) FROM outbox_job_attempts WHERE job_id = $1`, job.ID).Scan(&beforeAttempts); err != nil {
		t.Fatal(err)
	}
	if beforeStatus != "dead_letter" || beforeAttempts != 0 {
		t.Fatalf("nested rollback status=%q attempts=%d", beforeStatus, beforeAttempts)
	}
	status, first, err := command.ReplayIdempotent(ctx, operator, "POST", path, "same-key", []byte("{}"), job.ID)
	if err != nil || status != 200 || first == nil {
		t.Fatalf("replay status=%d response=%#v err=%v", status, first, err)
	}
	status, replayed, err := command.ReplayIdempotent(ctx, operator, "POST", path, "same-key", []byte("{}"), job.ID)
	if err != nil || status != 200 || replayed == nil {
		t.Fatalf("idempotent replay status=%d response=%#v err=%v", status, replayed, err)
	}
	if _, _, err := command.ReplayIdempotent(ctx, wildcard, "POST", path, "same-key", []byte("{}"), job.ID); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("downgraded actor replay err=%v, want forbidden", err)
	}
	var jobStatus string
	var attempts, audits, completions int
	if err := scoped.QueryRow(ctx, `SELECT status FROM outbox_jobs WHERE id = $1`, job.ID).Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if err := scoped.QueryRow(ctx, `SELECT count(*) FROM outbox_job_attempts WHERE job_id = $1`, job.ID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := scoped.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries WHERE tenant_id = $1 AND entry_type = 'outbox_job.replayed'`, job.TenantID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := scoped.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE state = 'completed'`).Scan(&completions); err != nil {
		t.Fatal(err)
	}
	if jobStatus != "queued" || attempts != 1 || audits != 1 || completions != 1 {
		t.Fatalf("replay status=%s attempts=%d audits=%d completions=%d", jobStatus, attempts, audits, completions)
	}
	if firstReplay, ok := first.(app.OutboxReplay); !ok || firstReplay.JobID != job.ID || firstReplay.Status != "queued" {
		t.Fatalf("unexpected first replay response: %#v", first)
	}
	if strings.Contains(fmt.Sprint(replayed), "payload_hash") || strings.Contains(fmt.Sprint(replayed), "ten_replay_command") {
		t.Fatalf("replay exposed payload or tenant metadata: %#v", replayed)
	}
}
