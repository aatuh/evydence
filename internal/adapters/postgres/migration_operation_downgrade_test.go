package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestManagedMigrationAuditDowngradeCannotRaceCommittedOperation(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	up, err := os.ReadFile("../../../migrations/20261104000100_migration_operation_audit.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.migrator.pool.Exec(f.ctx, string(up)); err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/20261104000100_migration_operation_audit.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.migrator.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	result := make(chan error, 1)
	started := false
	t.Cleanup(func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(f.ctx), 6*time.Second)
		defer stop()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("cannot roll back owned audit writer", err)
		}
		if started {
			select {
			case err := <-result:
				if err != nil && !errors.Is(err, context.Canceled) {
					var pe *pgconn.PgError
					if !errors.As(err, &pe) || pe.Code != "55000" {
						t.Error("cannot join audit downgrade", err)
					}
				}
			case <-cleanup.Done():
				t.Error("audit downgrade did not join")
			}
		}
	})
	if _, err := tx.Exec(f.ctx, `INSERT INTO schema_migration_operations(sequence,operation_id,phase,target_version,runtime_role,committed_migrations,policy_sha256)VALUES(1,'concurrent-operation','started','a',session_user,0,repeat('a',64))`); err != nil {
		t.Fatal(err)
	}
	go func() { _, err := f.migrator.pool.Exec(ctx, string(down)); result <- err }()
	started = true
	wait, stop := context.WithTimeout(f.ctx, 5*time.Second)
	defer stop()
	for {
		var waiting bool
		if err := f.admin.QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks locks JOIN pg_catalog.pg_class relation ON relation.oid=locks.relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace WHERE namespace.nspname=$1 AND relation.relname='schema_migration_operations' AND locks.mode='AccessExclusiveLock' AND NOT locks.granted)`, f.schema).Scan(&waiting); err != nil {
			t.Fatal("downgrade did not reach its owned audit lock barrier", err)
		}
		if waiting {
			break
		}
		select {
		case <-wait.Done():
			t.Fatal("downgrade did not wait on the in-flight audit record")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		started = false
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55000" {
			t.Fatal("downgrade lost an operation committed while it waited", err)
		}
	case <-f.ctx.Done():
		t.Fatal("downgrade did not finish after the audit commit")
	}
	var count int
	if err := f.migrator.pool.QueryRow(f.ctx, `SELECT count(*) FROM schema_migration_operations WHERE operation_id='concurrent-operation'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("downgrade failed to preserve the concurrently committed operation", count, err)
	}
}
