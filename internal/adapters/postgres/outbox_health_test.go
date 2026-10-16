package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
)

func TestOutboxReadinessDetectsStallsAndRecoversWithoutMutation(t *testing.T) {
	s := isolatedRelationalTestStore(t)
	ctx := t.Context()
	// Use PostgreSQL's read-only pool: a readiness check must never claim,
	// renew, replay or otherwise mutate a tenant's work.
	probe := &Store{pool: s.packageReadPool}
	if err := probe.CheckOutboxReadiness(ctx); err != nil {
		t.Fatalf("empty outbox: %v", err)
	}
	for _, tenant := range []string{"tenant", "foreign_tenant"} {
		if _, err := s.pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []string{"tenant", "foreign_tenant"} {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO outbox_jobs(id,tenant_id,kind,subject_type,subject_id,status,deduplication_key,payload,created_at)
			VALUES($1,$1,'parse_sbom','sbom','private-subject','queued',$1,'{"token":"private-payload"}',now()-interval '1 year')
		`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, status, runAfter, lockedAt string
		unavailable                      bool
	}{
		{"recent queued", "queued", "now()", "NULL", false},
		{"future queued", "queued", "now()+interval '1 hour'", "NULL", false},
		{"overdue queued", "queued", "now()-interval '6 minutes'", "NULL", true},
		{"future retry", "retrying", "now()+interval '1 hour'", "NULL", false},
		{"recent retry", "retrying", "now()-interval '1 minute'", "NULL", false},
		{"overdue retry", "retrying", "now()-interval '6 minutes'", "NULL", true},
		{"active lease", "running", "now()-interval '1 hour'", "now()", false},
		{"expired lease", "running", "now()", "now()-interval '6 minutes'", true},
		{"missing lease", "running", "now()", "NULL", true},
		{"dead letter", "dead_letter", "now()-interval '1 year'", "NULL", false},
		{"succeeded", "succeeded", "now()-interval '1 year'", "NULL", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Both tenants are operational dependencies. No row identifiers,
			// subject data or payloads may become a probe result.
			for _, tenant := range []string{"tenant", "foreign_tenant"} {
				if _, err := s.pool.Exec(ctx, `UPDATE outbox_jobs SET status='succeeded'`); err != nil {
					t.Fatal(err)
				}
				if _, err := s.pool.Exec(ctx, `UPDATE outbox_jobs SET status=$1,run_after=`+tc.runAfter+`,locked_at=`+tc.lockedAt+` WHERE id=$2`, tc.status, tenant); err != nil {
					t.Fatal(err)
				}
				before := outboxHealthRows(ctx, t, s)
				err := probe.CheckOutboxReadiness(ctx)
				if (err != nil) != tc.unavailable {
					t.Fatalf("tenant=%s unavailable=%v err=%v", tenant, tc.unavailable, err)
				}
				if err != nil && strings.Contains(err.Error(), "private-") {
					t.Fatal("health disclosed stored data")
				}
				if after := outboxHealthRows(ctx, t, s); after != before {
					t.Fatal("health mutated durable jobs")
				}
				if _, err := s.pool.Exec(ctx, `UPDATE outbox_jobs SET status='succeeded'`); err != nil {
					t.Fatal(err)
				}
				if err := probe.CheckOutboxReadiness(ctx); err != nil {
					t.Fatalf("did not recover after completion: %v", err)
				}
			}
		})
	}
	var sideEffects int
	if err := s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM outbox_job_attempts)+(SELECT count(*) FROM audit_chain_entries)`).Scan(&sideEffects); err != nil || sideEffects != 0 {
		t.Fatalf("health side effects=%d err=%v", sideEffects, err)
	}
}

func outboxHealthRows(ctx context.Context, t *testing.T, s *Store) string {
	t.Helper()
	var rows string
	if err := s.pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(j) ORDER BY id)::text FROM outbox_jobs j`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestOutboxReadinessHonorsCancellationAndPoolDeadline(t *testing.T) {
	s := isolatedRelationalTestStore(t)
	for _, invalid := range []*Store{nil, {}} {
		if err := invalid.CheckOutboxReadiness(t.Context()); !errors.Is(err, app.ErrValidation) {
			t.Fatalf("invalid store: %v", err)
		}
	}
	if err := s.CheckOutboxReadiness(nil); !errors.Is(err, app.ErrValidation) { //nolint:staticcheck // Verify invalid caller input fails without panic.
		t.Fatalf("nil context: %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.CheckOutboxReadiness(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	config := s.pool.Config()
	config.MaxConns, config.MinConns, config.MinIdleConns = 1, 0, 0
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	held, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	probe := &Store{pool: pool}
	deadline, stop := context.WithTimeout(t.Context(), 100*time.Millisecond)
	err = probe.CheckOutboxReadiness(deadline)
	stop()
	held.Release()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pool deadline: %v", err)
	}
	if err := probe.CheckOutboxReadiness(t.Context()); err != nil {
		t.Fatalf("pool did not recover: %v", err)
	}
	pool.Close()
	if err := probe.CheckOutboxReadiness(t.Context()); err == nil {
		t.Fatal("closed database reported healthy")
	}
}
