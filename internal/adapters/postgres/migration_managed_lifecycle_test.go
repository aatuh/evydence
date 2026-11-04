package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestManagedMigrationHoldsCoordinatorThroughGrantAuditCommit(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	const barrier int32 = 0x6576797a
	if _, err := f.admin.Exec(f.ctx, `SELECT pg_catalog.pg_advisory_lock($1,pg_catalog.hashtext($2))`, barrier, f.schema); err != nil {
		t.Fatal(err)
	}
	held := true
	jobCtx, cancelJob := context.WithCancel(f.ctx)
	result := make(chan error, 1)
	started := false
	t.Cleanup(func() {
		cancelJob()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), 6*time.Second)
		defer cancel()
		if held {
			if _, err := f.admin.Exec(cleanup, `SELECT pg_catalog.pg_advisory_unlock($1,pg_catalog.hashtext($2))`, barrier, f.schema); err != nil {
				t.Error("cannot release owned grant-commit barrier")
			}
		}
		if started {
			select {
			case err := <-result:
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					t.Error("managed migration cleanup failed", err)
				}
			case <-cleanup.Done():
				t.Error("managed migration did not join after cancellation")
			}
		}
	})
	body := fmt.Sprintf(`CREATE TABLE managed_records(id integer);
CREATE FUNCTION hold_managed_commit() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN IF NEW.phase='succeeded' THEN PERFORM pg_catalog.pg_advisory_xact_lock(%d,pg_catalog.hashtext(pg_catalog.current_schema())); END IF; RETURN NEW; END $body$;
CREATE TRIGGER hold_managed_commit BEFORE INSERT ON schema_migration_operations FOR EACH ROW EXECUTE FUNCTION hold_managed_commit();`, barrier)
	dir, sums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": body})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "a", sums)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := f.migrator.ApplyMigrationPlan(jobCtx, plan.WithRuntimeRole(f.runtime))
		result <- err
	}()
	started = true
	wait, cancelWait := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancelWait()
	for {
		var waiting bool
		if err := f.admin.QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks locks JOIN pg_catalog.pg_stat_activity activity ON activity.pid=locks.pid WHERE locks.locktype='advisory' AND NOT locks.granted AND locks.classid=$1::oid AND activity.usename=$2)`, barrier, f.owner).Scan(&waiting); err != nil {
			t.Fatal("migration did not reach its grant/audit commit barrier")
		}
		if waiting {
			break
		}
		select {
		case <-wait.Done():
			t.Fatal("migration did not wait at its grant/audit commit")
		case <-time.After(5 * time.Millisecond):
		}
	}
	reader, cancelReader := context.WithTimeout(f.ctx, 150*time.Millisecond)
	err = f.application.CheckMigrationState(reader, dir)
	cancelReader()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("runtime acquired the schema coordinator before grant/audit commit", err)
	}
	if _, err := f.admin.Exec(f.ctx, `SELECT pg_catalog.pg_advisory_unlock($1,pg_catalog.hashtext($2))`, barrier, f.schema); err != nil {
		t.Fatal(err)
	}
	held = false
	select {
	case err := <-result:
		started = false
		if err != nil {
			t.Fatal("managed grant/audit commit failed", err)
		}
	case <-f.ctx.Done():
		t.Fatal("managed grant commit did not finish")
	}
	if err := f.application.CheckMigrationState(f.ctx, dir); err != nil {
		t.Fatal("completed managed commit did not admit runtime", err)
	}
}

func TestManagedMigrationAuditDowngradePreservesRecordedOperations(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		t.Run(fmt.Sprint(recorded), func(t *testing.T) {
			f := newMigrationRoleFixture(t, false)
			if recorded {
				dir, sums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "SELECT 1;"})
				plan, err := PrepareMigrationPlan(f.ctx, dir, "a", sums)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.migrator.ApplyMigrationPlan(f.ctx, plan.WithRuntimeRole(f.runtime)); err != nil {
					t.Fatal(err)
				}
			} else {
				up, err := os.ReadFile("../../../migrations/20261104000100_migration_operation_audit.up.sql")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.migrator.pool.Exec(f.ctx, string(up)); err != nil {
					t.Fatal(err)
				}
			}
			down, err := os.ReadFile("../../../migrations/20261104000100_migration_operation_audit.down.sql")
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.migrator.pool.Exec(f.ctx, string(down))
			if recorded {
				var postgresError *pgconn.PgError
				if !errors.As(err, &postgresError) || postgresError.Code != "55000" {
					t.Fatal("downgrade erased or failed to protect recorded operations")
				}
				var count int
				if err := f.migrator.pool.QueryRow(f.ctx, "SELECT count(*) FROM schema_migration_operations").Scan(&count); err != nil || count != 2 {
					t.Fatal("downgrade changed recorded operation rows")
				}
			} else if err != nil {
				t.Fatal("empty operation metadata could not be downgraded", err)
			}
		})
	}
}

func TestMigrationPlanRejectsInvalidRuntimeRoleWithoutDatabase(t *testing.T) {
	dir, sums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "SELECT 1;"})
	plan, err := PrepareMigrationPlan(t.Context(), dir, "a", sums)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"", " ", "role\n", fmt.Sprintf("%064d", 0), string([]byte{0xff})} {
		count, err := (*Store)(nil).ApplyMigrationPlan(t.Context(), plan.WithRuntimeRole(role))
		if count != 0 || !errors.Is(err, ErrMigrationRuntimeRole) {
			t.Fatal("invalid role reached database acquisition", count, err)
		}
	}
}

func TestManagedMigrationRuntimeRejectsChangedPolicyOrTarget(t *testing.T) {
	for _, field := range []string{"policy_sha256", "target_version"} {
		t.Run(field, func(t *testing.T) {
			f := newMigrationRoleFixture(t, false)
			dir, sums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "SELECT 1;"})
			plan, err := PrepareMigrationPlan(f.ctx, dir, "a", sums)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.migrator.ApplyMigrationPlan(f.ctx, plan.WithRuntimeRole(f.runtime)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.migrator.pool.Exec(f.ctx, `INSERT INTO schema_migration_operations(sequence,operation_id,phase,target_version,runtime_role,committed_migrations,policy_sha256)SELECT sequence+1,'changed-marker','succeeded',target_version,runtime_role,0,policy_sha256 FROM schema_migration_operations ORDER BY sequence DESC LIMIT 1`); err != nil {
				t.Fatal(err)
			}
			value := "wrong-target"
			if field == "policy_sha256" {
				value = fmt.Sprintf("%064d", 0)
			}
			if _, err := f.migrator.pool.Exec(f.ctx, "UPDATE schema_migration_operations SET "+pgx.Identifier{field}.Sanitize()+"=$1 WHERE operation_id='changed-marker'", value); err != nil {
				t.Fatal(err)
			}
			if err := f.application.CheckMigrationState(f.ctx, dir); !errors.Is(err, ErrMigrationRuntimeNotReady) {
				t.Fatal("runtime accepted a mismatched operation policy/target", err)
			}
		})
	}
}
