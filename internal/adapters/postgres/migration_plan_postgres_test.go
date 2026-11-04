package postgres

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMigrationPlanAppliesFrozenPrefixAndNoop(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	dir, checksums := writeMigrationPlanFixture(t, map[string]string{
		"a.up.sql": "INSERT INTO migration_effects(value)VALUES(1);",
		"b.up.sql": "INSERT INTO migration_effects(value)VALUES(2);",
		"c.up.sql": "INSERT INTO migration_effects(value)VALUES(99);", "a.down.sql": "SELECT 1/0;"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "b", checksums)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.up.sql"), []byte("SELECT 1/0;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "b.up.sql")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(checksums); err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{2, 0} {
		if count, err := f.stores[i].ApplyMigrationPlan(f.ctx, plan); err != nil || count != want {
			t.Fatal("verified plan changed its frozen SQL, target or no-op result", count, err)
		}
	}
	f.requireCounts(2, 2)
	var total int
	if err := f.admin.QueryRow(f.ctx, "SELECT sum(value) FROM "+f.quoted+".migration_effects").Scan(&total); err != nil || total != 3 {
		t.Fatal("plan executed SQL outside its verified target", total, err)
	}
}

func TestMigrationPlanRejectsIncompatibleHistoryBeforeSQL(t *testing.T) {
	for _, version := range []string{"c", "PRIVATE_UNKNOWN", "b"} {
		t.Run(version, func(t *testing.T) {
			f := newMigrationRunnerTestFixture(t)
			if _, err := f.admin.Exec(f.ctx, "INSERT INTO "+f.quoted+".schema_migrations(version)VALUES($1)", version); err != nil {
				t.Fatal(err)
			}
			dir, checksums := writeMigrationPlanFixture(t, map[string]string{
				"a.up.sql": "INSERT INTO migration_effects(value)VALUES(1);",
				"b.up.sql": "INSERT INTO migration_effects(value)VALUES(2);", "c.up.sql": "SELECT 1;"})
			plan, err := PrepareMigrationPlan(f.ctx, dir, "b", checksums)
			if err != nil {
				t.Fatal(err)
			}
			count, err := f.stores[0].ApplyMigrationPlan(f.ctx, plan)
			if count != 0 || !errors.Is(err, ErrMigrationHistory) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("newer, unknown or gapped history reached migration SQL", count, err)
			}
			f.requireCounts(0, 1)
			ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
			defer cancel()
			runner, err := f.stores[1].acquireMigrationRunner(ctx)
			if err != nil {
				t.Fatal("history rejection retained runner coordination", err)
			}
			if err := runner.release(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMigrationPlanPreservesLegacyVersionRows(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	if _, err := f.admin.Exec(f.ctx, "INSERT INTO "+f.quoted+".schema_migrations(version,applied_at)VALUES('a','2001-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	dir, checksums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "SELECT 1/0;", "b.up.sql": "INSERT INTO migration_effects(value)VALUES(2);"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "b", checksums)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := f.stores[0].ApplyMigrationPlan(f.ctx, plan.WithLegacyHistory()); err != nil || count != 1 {
		t.Fatal("plan rewrote a legacy version or failed its pending suffix", count, err)
	}
	f.requireCounts(1, 2)
	var unchanged bool
	if err := f.admin.QueryRow(f.ctx, "SELECT applied_at='2001-01-01T00:00:00Z'::timestamptz FROM "+f.quoted+".schema_migrations WHERE version='a'").Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("legacy migration timestamp was rewritten", err)
	}
}

func TestMigrationPlanSQLFailurePreservesCommittedPrefix(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	bodies := map[string]string{"a.up.sql": "INSERT INTO migration_effects(value)VALUES(1);", "b.up.sql": "INSERT INTO migration_effects(value)VALUES(2); SELECT 1/0;"}
	dir, checksums := writeMigrationPlanFixture(t, bodies)
	plan, err := PrepareMigrationPlan(f.ctx, dir, "b", checksums)
	if err != nil {
		t.Fatal(err)
	}
	count, err := f.stores[0].ApplyMigrationPlan(f.ctx, plan)
	var databaseError *pgconn.PgError
	if count != 1 || !errors.As(err, &databaseError) || databaseError.Code != "22012" {
		t.Fatal("plan lost its committed prefix or SQL failure", count, err)
	}
	f.requireCounts(1, 1)
	bodies["b.up.sql"] = "INSERT INTO migration_effects(value)VALUES(2);"
	dir, checksums = writeMigrationPlanFixture(t, bodies)
	plan, err = PrepareMigrationPlan(f.ctx, dir, "b", checksums)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := f.stores[1].ApplyMigrationPlan(f.ctx, plan); err != nil || count != 1 {
		t.Fatal("valid forward retry did not continue its recorded prefix", count, err)
	}
	f.requireCounts(2, 2)
}

func TestMigrationPlanSessionsSerializePrefixChecks(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	dir, checksums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "INSERT INTO migration_effects(value)VALUES(1);", "b.up.sql": "INSERT INTO migration_effects(value)VALUES(2);"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "b", checksums)
	if err != nil {
		t.Fatal(err)
	}
	f.hold(migrationRunnerLockNamespace)
	results := make(chan migrationRunnerTestResult, 2)
	for _, store := range f.stores {
		f.workers.Add(1)
		go func() {
			defer f.workers.Done()
			count, err := store.ApplyMigrationPlan(f.ctx, plan)
			results <- migrationRunnerTestResult{count, err}
		}()
	}
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	for {
		var waiting int
		if err := f.admin.QueryRow(ctx, `SELECT count(DISTINCT locks.pid) FROM pg_locks locks JOIN pg_stat_activity activity ON activity.pid=locks.pid WHERE locks.locktype='advisory' AND NOT locks.granted AND activity.application_name=$1`, f.application).Scan(&waiting); err != nil {
			t.Fatal("plan sessions did not reach independent database waits", err)
		}
		if waiting == 2 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("both plan sessions did not reach the held database lock")
		case <-time.After(5 * time.Millisecond):
		}
	}
	f.unlock()
	applied := 0
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil || (result.count != 0 && result.count != 2) {
				t.Fatal("serialized plan execution failed", result.count, result.err)
			}
			applied += result.count
		case <-f.ctx.Done():
			t.Fatal("plan session did not finish")
		}
	}
	if applied != 2 {
		t.Fatal("concurrent plans applied duplicate effects", applied)
	}
	f.requireCounts(2, 2)
}

func TestMigrationPlanRejectsConflictingVersionRecordAtomically(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	dir, checksums := writeMigrationPlanFixture(t, map[string]string{"a.up.sql": "INSERT INTO schema_migrations(version)VALUES('a'); INSERT INTO migration_effects(value)VALUES(1);"})
	plan, err := PrepareMigrationPlan(f.ctx, dir, "a", checksums)
	if err != nil {
		t.Fatal(err)
	}
	count, err := f.stores[0].ApplyMigrationPlan(f.ctx, plan)
	var databaseError *pgconn.PgError
	if count != 0 || !errors.As(err, &databaseError) || databaseError.Code != "23505" {
		t.Fatal("conflicting version recording was silently accepted", count, err)
	}
	f.requireCounts(0, 0)
}
