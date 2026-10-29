package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/telemetry"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestOutboxTracePersistsAcrossRestartWithoutChangingTenantDeduplication(t *testing.T) {
	for _, transactional := range []bool{false, true} {
		name := "direct"
		if transactional {
			name = "transactional"
		}
		t.Run(name, func(t *testing.T) {
			store := isolatedRelationalTestStore(t)
			ctx := t.Context()
			first, _ := telemetry.NewTraceContext("0123456789abcdef0123456789abcdef", "0123456789abcdef", true)
			other, _ := telemetry.NewTraceContext("fedcba9876543210fedcba9876543210", "fedcba9876543210", false)
			for _, tenant := range []string{"ten_trace_a", "ten_trace_b"} {
				if _, err := store.pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
					t.Fatal(err)
				}
			}
			enqueue := func(ctx context.Context, job app.OutboxJob) error {
				if !transactional {
					return store.Enqueue(ctx, job)
				}
				u, err := store.BeginUnitOfWork(ctx)
				if err != nil {
					return err
				}
				defer func() { _ = u.Rollback(ctx) }()
				if err := u.Repositories().Outbox.Enqueue(ctx, job); err != nil {
					return err
				}
				return u.Commit(ctx)
			}
			job := app.OutboxJob{ID: "job_trace_a", TenantID: "ten_trace_a", Kind: "parse_sbom", SubjectType: "sbom", SubjectID: "same_subject", DeduplicationKey: "same_key", Payload: map[string]any{"source": "PRIVATE_EVIDENCE"}, CreatedAt: time.Now().UTC()}
			if err := enqueue(telemetry.WithTraceContext(ctx, first), job); err != nil {
				t.Fatal(err)
			}
			duplicate := job
			duplicate.ID = "job_trace_duplicate"
			if err := enqueue(telemetry.WithTraceContext(ctx, other), duplicate); err != nil {
				t.Fatal(err)
			}
			foreign := job
			foreign.ID, foreign.TenantID = "job_trace_b", "ten_trace_b"
			if err := enqueue(telemetry.WithTraceContext(ctx, other), foreign); err != nil {
				t.Fatal(err)
			}
			legacy := job
			legacy.ID, legacy.SubjectID, legacy.DeduplicationKey = "job_trace_legacy", "legacy_subject", "legacy_key"
			if err := enqueue(ctx, legacy); err != nil {
				t.Fatal(err)
			}
			// Rollback must discard metadata together with its job.
			u, err := store.BeginUnitOfWork(ctx)
			if err != nil {
				t.Fatal(err)
			}
			rolled := job
			rolled.ID, rolled.DeduplicationKey = "job_trace_rollback", "rollback_key"
			if err := u.Repositories().Outbox.Enqueue(telemetry.WithTraceContext(ctx, other), rolled); err != nil {
				t.Fatal(err)
			}
			if err := u.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_jobs`).Scan(&count); err != nil || count != 3 {
				t.Fatal("trace metadata changed deduplication, tenant scope or rollback", count, err)
			}
			var key, payload string
			if err := store.pool.QueryRow(ctx, `SELECT deduplication_key,payload->>'source' FROM outbox_jobs WHERE tenant_id=$1 AND id=$2`, job.TenantID, job.ID).Scan(&key, &payload); err != nil || key != job.DeduplicationKey || payload != "PRIVATE_EVIDENCE" {
				t.Fatal("operational metadata changed durable job content", err)
			}
			connection := store.pool.Config().ConnString()
			store.Close()
			reopened, err := OpenWithOptions(ctx, connection, StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			claims, err := reopened.ClaimJobs(ctx, 10)
			if err != nil || len(claims) != 3 {
				t.Fatal("restart lost durable jobs", err)
			}
			expected := map[string]telemetry.TraceContext{job.ID: first, foreign.ID: other, legacy.ID: {}}
			byID := map[string]ClaimedJob{}
			for _, claim := range claims {
				if carrier, ok := expected[claim.ID]; !ok || claim.TraceContext != carrier {
					t.Fatal("restart, duplicate or another tenant replaced the originating trace")
				}
				byID[claim.ID] = claim
			}
			if err := reopened.CompleteJob(ctx, job.ID, byID[foreign.ID].LeaseToken); !errors.Is(err, app.ErrConflict) {
				t.Fatal("trace metadata weakened cross-job lease fencing", err)
			}
			if _, err := reopened.pool.Exec(ctx, `UPDATE outbox_jobs SET locked_at=now()-interval '6 minutes' WHERE id=$1`, job.ID); err != nil {
				t.Fatal(err)
			}
			reclaimed, err := reopened.ClaimJobs(ctx, 1)
			if err != nil || len(reclaimed) != 1 || reclaimed[0].TraceContext != first || reclaimed[0].TenantID != job.TenantID {
				t.Fatal("reclaim lost tenant-bound trace context", err)
			}
			if err := reopened.CompleteJob(ctx, job.ID, byID[job.ID].LeaseToken); !errors.Is(err, app.ErrConflict) {
				t.Fatal("trace metadata weakened stale-worker fencing", err)
			}
		})
	}
}

func TestOutboxTraceConcurrentDuplicatesKeepWinningJobContext(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('ten_trace_race','race')`); err != nil {
		t.Fatal(err)
	}
	job := app.OutboxJob{TenantID: "ten_trace_race", Kind: "parse_sbom", SubjectType: "sbom", SubjectID: "same_subject", Payload: map[string]any{"source": "PRIVATE_EVIDENCE"}, CreatedAt: time.Now().UTC()}
	results := make(chan error, 8)
	expected := map[string]telemetry.TraceContext{}
	for i := 1; i <= cap(results); i++ {
		candidate := job
		candidate.ID = fmt.Sprintf("job_trace_racer_%d", i)
		carrier, _ := telemetry.NewTraceContext(fmt.Sprintf("%032x", i), fmt.Sprintf("%016x", i), true)
		expected[candidate.ID] = carrier
		go func() { results <- store.Enqueue(telemetry.WithTraceContext(ctx, carrier), candidate) }()
	}
	for range cap(results) {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	claims, err := store.ClaimJobs(ctx, 10)
	if err != nil || len(claims) != 1 {
		t.Fatal("concurrent trace carriers changed logical deduplication", err)
	}
	if claims[0].TraceContext != expected[claims[0].ID] {
		t.Fatal("a losing duplicate replaced the committed job's trace")
	}
}

func TestOutboxTraceDoesNotChangeFrozenBackupCommitment(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('ten_trace_backup','backup')`); err != nil {
		t.Fatal(err)
	}
	if err := store.Enqueue(ctx, app.OutboxJob{ID: "job_trace_backup", TenantID: "ten_trace_backup", Kind: "parse_sbom", SubjectType: "sbom", SubjectID: "backup_subject", Payload: map[string]any{"source": "original"}, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	reader := postgresrepositories.New(tx).Integrity.(verificationapp.BackupStateCommitmentReader)
	before, err := reader.ReadBackupStateCommitment(ctx, "ten_trace_backup")
	if err != nil || before.StateHash == "" {
		t.Fatal("could not compute the historical backup commitment", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE outbox_jobs SET trace_id='0123456789abcdef0123456789abcdef',trace_parent_span_id='0123456789abcdef',trace_sampled=true WHERE id='job_trace_backup'`); err != nil {
		t.Fatal(err)
	}
	withTrace, err := reader.ReadBackupStateCommitment(ctx, "ten_trace_backup")
	if err != nil || withTrace.StateHash != before.StateHash || withTrace.Profile != before.Profile || withTrace.BytesRead != before.BytesRead {
		t.Fatal("operational metadata changed the frozen backup format or commitment", err)
	}
	// Raw payloads are deliberately excluded by the historical profile. A
	// covered subject identifier is the positive control for commitment changes.
	if _, err := tx.Exec(ctx, `UPDATE outbox_jobs SET subject_id='changed_subject' WHERE id='job_trace_backup'`); err != nil {
		t.Fatal(err)
	}
	changed, err := reader.ReadBackupStateCommitment(ctx, "ten_trace_backup")
	if err != nil || changed.StateHash == before.StateHash || changed.RowsRead != before.RowsRead {
		t.Fatal("the frozen commitment stopped covering the durable job identity", err)
	}
}

func TestOutboxTraceMigrationPreservesPopulatedJobsAndRejectsInvalidMetadata(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	execute := func(direction string) {
		t.Helper()
		data, err := os.ReadFile("../../../migrations/20261028000100_outbox_trace_context." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, string(data)); err != nil {
			t.Fatal(err)
		}
	}
	execute("down")
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('ten_trace_old','old');
INSERT INTO outbox_jobs(id,tenant_id,kind,subject_type,subject_id,deduplication_key,payload,status)
VALUES('job_trace_old','ten_trace_old','parse_sbom','sbom','old','old_key','{"source":"PRIVATE_OLD_EVIDENCE"}','queued')`); err != nil {
		t.Fatal(err)
	}
	execute("up")
	var traceID, spanID, state, key, payload string
	var sampled bool
	if err := store.pool.QueryRow(ctx, `SELECT trace_id,trace_parent_span_id,trace_sampled,status,deduplication_key,payload->>'source' FROM outbox_jobs WHERE id='job_trace_old'`).Scan(&traceID, &spanID, &sampled, &state, &key, &payload); err != nil || traceID != "" || spanID != "" || sampled || state != "queued" || key != "old_key" || payload != "PRIVATE_OLD_EVIDENCE" {
		t.Fatal("upgrade changed a historical job or invented a trace", err)
	}
	for _, invalid := range []struct {
		trace, span string
		sampled     bool
	}{
		{"", "0123456789abcdef", false},
		{"0123456789abcdef0123456789abcdef", "", false},
		{"00000000000000000000000000000000", "0123456789abcdef", false},
		{"0123456789abcdef0123456789abcdef", "0000000000000000", false},
		{"0123456789ABCDEF0123456789ABCDEF", "0123456789abcdef", false},
		{"PRIVATE_UNTRUSTED_INPUT", "0123456789abcdef", false},
		{"", "", true},
	} {
		if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET trace_id=$1,trace_parent_span_id=$2,trace_sampled=$3 WHERE id='job_trace_old'`, invalid.trace, invalid.span, invalid.sampled); err == nil {
			t.Fatal("invalid metadata bypassed the storage constraint")
		}
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET trace_id='0123456789abcdef0123456789abcdef',trace_parent_span_id='0123456789abcdef',trace_sampled=true WHERE id='job_trace_old'`); err != nil {
		t.Fatal(err)
	}
	execute("down")
	if err := store.pool.QueryRow(ctx, `SELECT status,deduplication_key,payload->>'source' FROM outbox_jobs WHERE id='job_trace_old'`).Scan(&state, &key, &payload); err != nil || state != "queued" || key != "old_key" || payload != "PRIVATE_OLD_EVIDENCE" {
		t.Fatal("downgrade changed durable job content", err)
	}
	execute("up")
}

func TestOutboxTraceMigrationLockWaitRollsBackAndCanBeRetried(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	down, err := os.ReadFile("../../../migrations/20261028000100_outbox_trace_context.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../migrations/20261028000100_outbox_trace_context.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	locked, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = locked.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := locked.Exec(ctx, `SELECT 1 FROM outbox_jobs LIMIT 0`); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tx, err := store.pool.Begin(bounded)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	_, err = tx.Exec(bounded, string(up))
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "55P03" || bounded.Err() != nil {
		t.Fatal("migration did not stop at its own lock-wait budget")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var columns int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='outbox_jobs' AND column_name IN ('trace_id','trace_parent_span_id','trace_sampled')`).Scan(&columns); err != nil || columns != 0 {
		t.Fatal("failed migration left a partial operational schema", err)
	}
	if err := locked.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	retry, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = retry.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := retry.Exec(ctx, string(up)); err != nil {
		t.Fatal("migration could not recover after contention", err)
	}
	if err := retry.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
