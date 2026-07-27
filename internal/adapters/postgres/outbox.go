package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const outboxLeaseDuration = 5 * time.Minute

type JobFailureClass string

const (
	JobFailureTransient JobFailureClass = "transient"
	JobFailurePermanent JobFailureClass = "permanent"
	JobFailurePoisoned  JobFailureClass = "poisoned"
)

// JobFailure contains only a stable, safe operator code. Do not place raw
// database, object-store, provider, or payload errors in Code.
type JobFailure struct {
	Class JobFailureClass
	Code  string
}

func (f JobFailure) normalized() (JobFailure, error) {
	f.Class = JobFailureClass(strings.TrimSpace(string(f.Class)))
	f.Code = strings.TrimSpace(f.Code)
	if f.Code == "" || len(f.Code) > 96 {
		return JobFailure{}, app.ErrValidation
	}
	for _, r := range f.Code {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return JobFailure{}, app.ErrValidation
		}
	}
	if f.Class != JobFailureTransient && f.Class != JobFailurePermanent && f.Class != JobFailurePoisoned {
		return JobFailure{}, app.ErrValidation
	}
	return f, nil
}

type ClaimedJob struct {
	ID          string
	TenantID    string
	Kind        string
	SubjectType string
	SubjectID   string
	Attempts    int
	LeaseToken  string
	Payload     map[string]any
}

func (s *Store) Enqueue(ctx context.Context, job app.OutboxJob) error {
	return insertOutboxJob(ctx, s.pool, job)
}

type outboxExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func insertOutboxJob(ctx context.Context, exec outboxExecutor, job app.OutboxJob) error {
	if job.ID == "" || job.TenantID == "" || job.Kind == "" || job.SubjectType == "" || (job.SubjectID == "" && (job.Kind != "verify_subject" || job.SubjectType != "audit_chain")) || job.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := app.EnsureOutboxDeduplicationKey(&job); err != nil {
		return err
	}
	payload, err := json.Marshal(job.Payload)
	if err != nil {
		return fmt.Errorf("encode outbox payload: %w", err)
	}
	_, err = exec.Exec(ctx, `
		INSERT INTO outbox_jobs (
			id, tenant_id, kind, subject_type, subject_id, deduplication_key, payload, status,
			attempts, max_attempts, run_after, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'queued', 0, 5, now(), $8, now())
		ON CONFLICT (tenant_id, deduplication_key) DO NOTHING
	`, job.ID, job.TenantID, job.Kind, job.SubjectType, job.SubjectID, job.DeduplicationKey, payload, job.CreatedAt)
	if err != nil {
		return fmt.Errorf("enqueue outbox job: %w", err)
	}
	return nil
}

func insertOutboxJobTx(ctx context.Context, tx pgx.Tx, job app.OutboxJob) error {
	return insertOutboxJob(ctx, tx, job)
}

func (s *Store) ClaimJobs(ctx context.Context, limit int) ([]ClaimedJob, error) {
	if limit <= 0 {
		limit = 10
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin claim jobs transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		WITH terminal AS (
			UPDATE outbox_jobs
			SET status = 'dead_letter', terminal_at = now(), locked_at = NULL,
				lease_token = NULL, failure_class = 'transient', failure_code = 'lease_expired',
				last_error = 'lease_expired', updated_at = now()
			WHERE status = 'running' AND locked_at <= now() - $1 * interval '1 second' AND attempts >= max_attempts
			RETURNING id, attempts
		)
		INSERT INTO outbox_job_attempts (job_id, attempt, outcome, failure_class, failure_code)
		SELECT id, attempts, 'dead_letter', 'transient', 'lease_expired' FROM terminal
	`, int(outboxLeaseDuration/time.Second)); err != nil {
		return nil, fmt.Errorf("terminalize expired outbox leases: %w", err)
	}
	rows, err := tx.Query(ctx, `
		WITH claimed AS (
			SELECT id
			FROM outbox_jobs
			WHERE (status IN ('queued', 'retrying') AND run_after <= now())
			   OR (status = 'running' AND locked_at <= now() - $2 * interval '1 second' AND attempts < max_attempts)
			ORDER BY run_after, created_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE outbox_jobs j
		SET status = 'running',
		    attempts = attempts + 1,
		    locked_at = now(),
		    lease_token = md5(j.id || ':' || clock_timestamp()::text || ':' || random()::text),
		    updated_at = now()
		FROM claimed
		WHERE j.id = claimed.id
		RETURNING j.id, j.tenant_id, j.kind, j.subject_type, j.subject_id, j.attempts, j.lease_token, j.payload
	`, limit, int(outboxLeaseDuration/time.Second))
	if err != nil {
		return nil, fmt.Errorf("claim jobs: %w", err)
	}
	defer rows.Close()
	jobs := []ClaimedJob{}
	for rows.Next() {
		var job ClaimedJob
		var payload []byte
		if err := rows.Scan(&job.ID, &job.TenantID, &job.Kind, &job.SubjectType, &job.SubjectID, &job.Attempts, &job.LeaseToken, &payload); err != nil {
			return nil, fmt.Errorf("scan claimed job: %w", err)
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &job.Payload); err != nil {
				return nil, fmt.Errorf("decode claimed job payload: %w", err)
			}
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read claimed jobs: %w", err)
	}
	rows.Close()
	for _, job := range jobs {
		if _, err := tx.Exec(ctx, `INSERT INTO outbox_job_attempts (job_id, attempt, outcome) VALUES ($1, $2, 'claimed')`, job.ID, job.Attempts); err != nil {
			return nil, fmt.Errorf("record outbox claim attempt: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit claim jobs transaction: %w", err)
	}
	return jobs, nil
}

func (s *Store) CompleteJob(ctx context.Context, id, leaseToken string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin complete outbox job transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var attempts int
	err = tx.QueryRow(ctx, `
		UPDATE outbox_jobs
		SET status = 'succeeded', locked_at = NULL, lease_token = NULL, last_error = NULL,
			failure_class = NULL, failure_code = NULL, updated_at = now()
		WHERE id = $1 AND status = 'running' AND lease_token = $2
		RETURNING attempts
	`, id, leaseToken).Scan(&attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("complete outbox job: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO outbox_job_attempts (job_id, attempt, outcome) VALUES ($1, $2, 'succeeded')`, id, attempts); err != nil {
		return fmt.Errorf("record outbox completion: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit complete outbox job transaction: %w", err)
	}
	return nil
}

func (s *Store) FailJob(ctx context.Context, id, leaseToken string, failure JobFailure) error {
	failure, err := failure.normalized()
	if err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin fail outbox job transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var attempts int
	var status string
	err = tx.QueryRow(ctx, `
		UPDATE outbox_jobs
		SET status = CASE WHEN $3 = 'transient' AND attempts < max_attempts THEN 'retrying' ELSE 'dead_letter' END,
		    run_after = CASE WHEN $3 = 'transient' AND attempts < max_attempts THEN now() + make_interval(secs =>
				LEAST(300, POWER(2, attempts)::int) +
				((hashtext(id || ':' || attempts::text) & 2147483647) % GREATEST(1, LEAST(300, POWER(2, attempts)::int) / 4 + 1))
			) ELSE run_after END,
		    locked_at = NULL,
		    lease_token = NULL,
		    last_error = $4,
		    failure_class = $3,
		    failure_code = $4,
		    terminal_at = CASE WHEN $3 = 'transient' AND attempts < max_attempts THEN NULL ELSE now() END,
		    updated_at = now()
		WHERE id = $1 AND status = 'running' AND lease_token = $2
		RETURNING attempts, status
	`, id, leaseToken, failure.Class, failure.Code).Scan(&attempts, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("fail outbox job: %w", err)
	}
	outcome := "retrying"
	if status == "dead_letter" {
		outcome = "dead_letter"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO outbox_job_attempts (job_id, attempt, outcome, failure_class, failure_code) VALUES ($1, $2, $3, $4, $5)`, id, attempts, outcome, failure.Class, failure.Code); err != nil {
		return fmt.Errorf("record outbox failure: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit fail outbox job transaction: %w", err)
	}
	return nil
}

func (s *Store) CountPendingJobs(ctx context.Context) (int, error) {
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM outbox_jobs WHERE status IN ('queued', 'retrying', 'running')`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count outbox jobs: %w", err)
	}
	return count, nil
}

func (s *Store) OutboxDiagnostics(ctx context.Context) (app.OutboxDiagnostics, error) {
	var diagnostics app.OutboxDiagnostics
	var oldest *time.Time
	if err := s.pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE status IN ('queued', 'retrying')),
			count(*) FILTER (WHERE status = 'running'),
			count(*) FILTER (WHERE status = 'dead_letter'),
			min(created_at) FILTER (WHERE status IN ('queued', 'retrying'))
		FROM outbox_jobs
	`).Scan(&diagnostics.PendingJobs, &diagnostics.RunningJobs, &diagnostics.TerminalJobs, &oldest); err != nil {
		return app.OutboxDiagnostics{}, fmt.Errorf("read outbox diagnostics: %w", err)
	}
	if oldest != nil {
		diagnostics.OldestPendingCreatedAt = oldest.UTC()
	}
	return diagnostics, nil
}

func (s *Store) ReplayTerminalJob(ctx context.Context, id, actorID string) (app.OutboxReplay, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(actorID) == "" {
		return app.OutboxReplay{}, app.ErrValidation
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return app.OutboxReplay{}, fmt.Errorf("begin replay outbox job transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var tenantID string
	err = tx.QueryRow(ctx, `SELECT tenant_id FROM outbox_jobs WHERE id = $1 AND status = 'dead_letter' FOR UPDATE`, id).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.OutboxReplay{}, app.ErrNotFound
	}
	if err != nil {
		return app.OutboxReplay{}, fmt.Errorf("load terminal outbox job: %w", err)
	}
	var replayedAt time.Time
	if err := tx.QueryRow(ctx, `
		UPDATE outbox_jobs
		SET status = 'queued', attempts = 0, run_after = now(), locked_at = NULL, lease_token = NULL,
			failure_class = NULL, failure_code = NULL, last_error = NULL, terminal_at = NULL, updated_at = now()
		WHERE id = $1 AND status = 'dead_letter'
		RETURNING updated_at
	`, id).Scan(&replayedAt); err != nil {
		return app.OutboxReplay{}, fmt.Errorf("requeue terminal outbox job: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO outbox_job_attempts (job_id, attempt, outcome, failure_code) VALUES ($1, 0, 'replayed', 'operator_replay')`, id); err != nil {
		return app.OutboxReplay{}, fmt.Errorf("record outbox replay: %w", err)
	}
	entry, err := repositories.New(tx).Audit.Append(ctx, domain.AuditChainEntry{
		ID:          fmt.Sprintf("ace_outbox_replay_%s_%d", id, replayedAt.UnixNano()),
		TenantID:    tenantID,
		EntryType:   "outbox_job.replayed",
		SubjectType: "outbox_job",
		SubjectID:   id,
		ActorType:   "api_key",
		ActorID:     actorID,
		OccurredAt:  replayedAt,
	})
	if err != nil {
		return app.OutboxReplay{}, fmt.Errorf("audit outbox replay: %w", err)
	}
	_ = entry
	if err := tx.Commit(ctx); err != nil {
		return app.OutboxReplay{}, fmt.Errorf("commit replay outbox job transaction: %w", err)
	}
	return app.OutboxReplay{JobID: id, Status: "queued", ReplayedAt: replayedAt.UTC()}, nil
}
