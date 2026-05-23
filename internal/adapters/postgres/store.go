package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
)

type Store struct {
	pool *pgxpool.Pool
}

type ClaimedJob struct {
	ID          string
	TenantID    string
	Kind        string
	SubjectType string
	SubjectID   string
	Attempts    int
	Payload     map[string]any
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func (s *Store) LoadState(ctx context.Context) (app.PersistedState, bool, error) {
	var body []byte
	err := s.pool.QueryRow(ctx, `SELECT state FROM ledger_state WHERE id = 'default'`).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.PersistedState{}, false, nil
	}
	if err != nil {
		return app.PersistedState{}, false, fmt.Errorf("load ledger state: %w", err)
	}
	var state app.PersistedState
	if err := json.Unmarshal(body, &state); err != nil {
		return app.PersistedState{}, false, fmt.Errorf("decode ledger state: %w", err)
	}
	return state, true, nil
}

func (s *Store) SaveState(ctx context.Context, state app.PersistedState) error {
	body, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode ledger state: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO ledger_state (id, state, updated_at)
		VALUES ('default', $1, now())
		ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at
	`, body)
	if err != nil {
		return fmt.Errorf("save ledger state: %w", err)
	}
	return nil
}

func (s *Store) Enqueue(ctx context.Context, job app.OutboxJob) error {
	payload, err := json.Marshal(job.Payload)
	if err != nil {
		return fmt.Errorf("encode outbox payload: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO outbox_jobs (
			id, tenant_id, kind, subject_type, subject_id, payload, status,
			attempts, max_attempts, run_after, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, 'queued', 0, 5, now(), $7, now())
		ON CONFLICT (id) DO NOTHING
	`, job.ID, job.TenantID, job.Kind, job.SubjectType, job.SubjectID, payload, job.CreatedAt)
	if err != nil {
		return fmt.Errorf("enqueue outbox job: %w", err)
	}
	return nil
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
	rows, err := tx.Query(ctx, `
		WITH claimed AS (
			SELECT id
			FROM outbox_jobs
			WHERE status IN ('queued', 'retrying')
			  AND run_after <= now()
			ORDER BY run_after, created_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE outbox_jobs j
		SET status = 'running',
		    attempts = attempts + 1,
		    locked_at = now(),
		    updated_at = now()
		FROM claimed
		WHERE j.id = claimed.id
		RETURNING j.id, j.tenant_id, j.kind, j.subject_type, j.subject_id, j.attempts, j.payload
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("claim jobs: %w", err)
	}
	defer rows.Close()
	jobs := []ClaimedJob{}
	for rows.Next() {
		var job ClaimedJob
		var payload []byte
		if err := rows.Scan(&job.ID, &job.TenantID, &job.Kind, &job.SubjectType, &job.SubjectID, &job.Attempts, &payload); err != nil {
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
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit claim jobs transaction: %w", err)
	}
	return jobs, nil
}

func (s *Store) CompleteJob(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE outbox_jobs
		SET status = 'succeeded', locked_at = NULL, last_error = NULL, updated_at = now()
		WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("complete outbox job: %w", err)
	}
	return nil
}

func (s *Store) FailJob(ctx context.Context, id string, cause error) error {
	message := "job failed"
	if cause != nil {
		message = cause.Error()
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE outbox_jobs
		SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'retrying' END,
		    run_after = now() + make_interval(secs => LEAST(300, POWER(2, attempts)::int)),
		    locked_at = NULL,
		    last_error = $2,
		    updated_at = now()
		WHERE id = $1
	`, id, message)
	if err != nil {
		return fmt.Errorf("fail outbox job: %w", err)
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

func (s *Store) Now(ctx context.Context) (time.Time, error) {
	var now time.Time
	if err := s.pool.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
		return time.Time{}, fmt.Errorf("postgres now: %w", err)
	}
	return now, nil
}
