package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func TestRuntimeResourcesMigrationStateUsesKnownLocalVersionsWithoutWriting(t *testing.T) {
	s := isolatedRelationalTestStore(t)
	ctx := t.Context()
	names := migrationFileNames(t, "../../../migrations")
	resources, err := s.ReadRuntimeResources(ctx)
	if err != nil || !resources.Migrations.Known || resources.Migrations.Applied != int64(len(names)) || resources.Migrations.Pending != 0 || resources.Migrations.Unexpected != 0 {
		t.Fatal("runtime metrics lost the successfully checked migration expectations", err)
	}
	latest := strings.TrimSuffix(names[len(names)-1], ".up.sql")
	if _, err := s.pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version=$1`, latest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO schema_migrations(version)VALUES('PRIVATE_UNEXPECTED_VERSION')`); err != nil {
		t.Fatal(err)
	}
	var before, after string
	statement := `SELECT jsonb_agg(jsonb_build_array(version,applied_at) ORDER BY version)::text FROM schema_migrations`
	if err := s.pool.QueryRow(ctx, statement).Scan(&before); err != nil {
		t.Fatal(err)
	}
	resources, err = s.ReadRuntimeResources(ctx)
	if err != nil || !resources.Migrations.Known || resources.Migrations.Applied != int64(len(names)-1) || resources.Migrations.Pending != 1 || resources.Migrations.Unexpected != 1 {
		t.Fatal("runtime metrics confused pending, matched or unexpected versions", err)
	}
	if err := s.pool.QueryRow(ctx, statement).Scan(&after); err != nil || before != after {
		t.Fatal("migration metrics changed migration records", err)
	}
	encoded, err := json.Marshal(resources)
	if err != nil || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), latest) {
		t.Fatal("migration metrics returned raw version identifiers", err)
	}
	// A fresh unconfigured store cannot claim that zero pending means current.
	unknown := &Store{pool: s.pool, packageReadPool: s.packageReadPool}
	resources, err = unknown.ReadRuntimeResources(ctx)
	if err != nil || resources.Migrations != (telemetry.MigrationResources{}) {
		t.Fatal("unknown local expectations were reported as current", err)
	}
}

func TestRuntimeResourcesReadOnlyScalarProjectionWithoutAggregate(t *testing.T) {
	s := isolatedRelationalTestStore(t)
	ctx := t.Context()
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"PRIVATE_TENANT_A", "PRIVATE_TENANT_B"} {
		if _, err := s.pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatal(err)
		}
		for _, status := range []string{"queued", "retrying", "running", "succeeded", "dead_letter"} {
			if _, err := s.pool.Exec(ctx, `
				INSERT INTO outbox_jobs(id,tenant_id,kind,subject_type,subject_id,status,deduplication_key,payload,attempts,created_at,updated_at)
				VALUES($1,$2,'parse_sbom','sbom','PRIVATE_CUSTOMER_ID',$3,$1,'{"token":"PRIVATE_TOKEN"}',3,$4,$4)
			`, tenant+status, tenant, status, created); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := s.pool.Exec(ctx, `UPDATE outbox_jobs SET run_after=now()-interval '10 minutes' WHERE tenant_id='PRIVATE_TENANT_A' AND status IN ('queued','retrying')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE outbox_jobs SET run_after=now()+interval '1 hour' WHERE tenant_id='PRIVATE_TENANT_B' AND status='retrying'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE outbox_jobs SET locked_at=now() WHERE tenant_id='PRIVATE_TENANT_A' AND status='running'`); err != nil {
		t.Fatal(err)
	}
	before := outboxHealthRows(ctx, t, s)
	// Aggregate loading would block on these tenant/evidence/key tables. The
	// operational query must touch only outbox scalar columns, never payloads.
	blocked, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocked.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := blocked.Exec(ctx, `LOCK TABLE evidence_items, artifacts, signing_keys, api_keys IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	held, err := s.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	resources, err := s.ReadRuntimeResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	queue := resources.Queue
	if queue.Queued != 2 || queue.Retrying != 2 || queue.Running != 2 || queue.Succeeded != 2 || queue.DeadLetter != 2 || queue.Attempts != 30 || !queue.OldestPendingAt.Equal(created) || queue.EligiblePending != 3 || queue.OverduePending != 2 || queue.ExpiredLeases != 1 || !queue.OldestEligibleAt.Equal(created) {
		t.Fatal("runtime queue projection lost actual cross-tenant scalar counts", queue)
	}
	if resources.PrimaryPool.Acquired < 2 || resources.PrimaryPool.Max < resources.PrimaryPool.Acquired || resources.ReadPool.Acquired != 0 || resources.ReadPool.Acquires < 1 || resources.ReadPool.Max < 1 {
		t.Fatal("runtime pool projection does not reflect live primary/read pools", resources)
	}
	encoded, err := json.Marshal(resources)
	if err != nil || strings.Contains(string(encoded), "PRIVATE") {
		t.Fatal("runtime projection disclosed stored identities or payloads", err)
	}
	if after := outboxHealthRows(ctx, t, s); after != before {
		t.Fatal("runtime metrics mutated durable jobs")
	}
	var sideEffects int
	if err := s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM outbox_job_attempts)+(SELECT count(*) FROM audit_chain_entries)`).Scan(&sideEffects); err != nil || sideEffects != 0 {
		t.Fatal("runtime metrics wrote attempts or audit records", sideEffects, err)
	}
	var readOnly bool
	if err := s.packageReadPool.QueryRow(ctx, `SELECT current_setting('default_transaction_read_only')::boolean`).Scan(&readOnly); err != nil || !readOnly {
		t.Fatal("runtime snapshot pool is not read-only", err)
	}
}

func TestRuntimeResourcesCancellationPoolDeadlineAndRecovery(t *testing.T) {
	s := isolatedRelationalTestStore(t)
	for _, invalid := range []*Store{nil, {}, {pool: s.pool}} {
		resources, err := invalid.ReadRuntimeResources(t.Context())
		if !errors.Is(err, app.ErrValidation) || resources != (telemetry.RuntimeResources{}) {
			t.Fatal("invalid metrics store returned data", err)
		}
	}
	for _, invalidContext := range []context.Context{nil} {
		resources, err := s.ReadRuntimeResources(invalidContext)
		if !errors.Is(err, app.ErrValidation) || resources != (telemetry.RuntimeResources{}) {
			t.Fatal("nil metrics context returned data", err)
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if resources, err := s.ReadRuntimeResources(canceled); !errors.Is(err, context.Canceled) || resources != (telemetry.RuntimeResources{}) {
		t.Fatal("canceled metrics read returned data", err)
	}
	config := s.packageReadPool.Config()
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
	defer held.Release()
	probe := &Store{pool: s.pool, packageReadPool: pool}
	started := time.Now()
	resources, err := probe.ReadRuntimeResources(t.Context())
	if !errors.Is(err, context.DeadlineExceeded) || resources != (telemetry.RuntimeResources{}) || time.Since(started) > 3*time.Second {
		t.Fatal("saturated metrics pool exceeded its own bound or returned partial data", err)
	}
	held.Release()
	resources, err = probe.ReadRuntimeResources(t.Context())
	if err != nil || resources.Queue.Queued != 0 || !resources.Queue.OldestPendingAt.IsZero() || resources.ReadPool.CanceledAcquires < 1 {
		t.Fatal("metrics did not recover after pool exhaustion", err)
	}
	pool.Close()
	if resources, err := probe.ReadRuntimeResources(t.Context()); err == nil || resources != (telemetry.RuntimeResources{}) {
		t.Fatal("closed metrics pool returned data", err)
	}
}
