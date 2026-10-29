package postgres

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func migrationReadOnlyStore(t *testing.T, fixture *migrationRunnerTestFixture) *Store {
	return migrationReadOnlyStoreWithSearchPath(t, fixture, fixture.schema)
}

func migrationReadOnlyStoreWithSearchPath(t *testing.T, fixture *migrationRunnerTestFixture, searchPath string) *Store {
	t.Helper()
	store := fixture.stores[0]
	config := store.pool.Config()
	config.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	config.ConnConfig.RuntimeParams["search_path"] = searchPath
	pool, err := pgxpool.NewWithConfig(fixture.ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	store.pool.Close()
	store.pool = pool
	var readOnly string
	if err := pool.QueryRow(fixture.ctx, `SHOW transaction_read_only`).Scan(&readOnly); err != nil || readOnly != "on" {
		t.Fatal("fixture connection is not actually read-only", readOnly, err)
	}
	return store
}

func TestMigrationStateCheckPreservesCatalogOrderAndScope(t *testing.T) {
	fixture := newMigrationRunnerTestFixture(t)
	store := migrationReadOnlyStore(t, fixture)
	dir := t.TempDir()
	for _, version := range []string{"b", "Z", "a"} {
		if err := os.WriteFile(filepath.Join(dir, version+".up.sql"), []byte("SELECT 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.admin.Exec(fixture.ctx, "INSERT INTO "+fixture.quoted+".schema_migrations(version)VALUES('a'),('PRIVATE_UNRELATED_HISTORY')"); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingMigrationVersions(fixture.ctx, dir)
	if err != nil || !reflect.DeepEqual(pending, []string{"Z", "b"}) {
		t.Fatal("state check changed catalog order or disclosed unrelated history", pending, err)
	}
	fixture.requireCounts(0, 2)
}

func TestMigrationStateCheckDoesNotUseFallbackSchemaTracking(t *testing.T) {
	fixture := newMigrationRunnerTestFixture(t)
	fallback := fixture.schema + "_fallback"
	quotedFallback := pgx.Identifier{fallback}.Sanitize()
	if _, err := fixture.admin.Exec(fixture.ctx, "CREATE SCHEMA "+quotedFallback); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(fixture.ctx), 5*time.Second)
		defer cancel()
		if _, err := fixture.admin.Exec(cleanup, "DROP SCHEMA "+quotedFallback+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	if _, err := fixture.admin.Exec(fixture.ctx, "DROP TABLE "+fixture.quoted+".schema_migrations; CREATE TABLE "+quotedFallback+".schema_migrations(version text PRIMARY KEY); INSERT INTO "+quotedFallback+".schema_migrations(version)VALUES('20261029000001_cleanup_probe')"); err != nil {
		t.Fatal(err)
	}
	searchPath := pgx.Identifier{fixture.schema}.Sanitize() + "," + quotedFallback
	store := migrationReadOnlyStoreWithSearchPath(t, fixture, searchPath)
	pending, err := store.PendingMigrationVersions(fixture.ctx, fixture.writeMigration("SELECT 1;"))
	if err != nil || !reflect.DeepEqual(pending, []string{"20261029000001_cleanup_probe"}) {
		t.Fatal("another schema's tracking made an uninitialized schema appear current", pending, err)
	}
	var exists bool
	if err := fixture.admin.QueryRow(fixture.ctx, `SELECT to_regclass($1) IS NOT NULL`, fixture.quoted+".schema_migrations").Scan(&exists); err != nil || exists {
		t.Fatal("checking fallback schema state created tracking", err)
	}
}

type migrationStateCheckResult struct {
	pending []string
	err     error
}

func startMigrationStateCheck(fixture *migrationRunnerTestFixture, store *Store, ctx context.Context, dir string) <-chan migrationStateCheckResult {
	result := make(chan migrationStateCheckResult, 1)
	fixture.workers.Add(1)
	go func() {
		defer fixture.workers.Done()
		pending, err := store.PendingMigrationVersions(ctx, dir)
		result <- migrationStateCheckResult{pending, err}
	}()
	return result
}

func requireMigrationStateCheckWaiting(t *testing.T, fixture *migrationRunnerTestFixture, result <-chan migrationStateCheckResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(fixture.ctx, 5*time.Second)
	defer cancel()
	for {
		select {
		case result := <-result:
			t.Fatal("migration check finished while an exclusive runner was active", result.pending, result.err)
		default:
		}
		var waiting int
		if err := fixture.admin.QueryRow(ctx, `SELECT count(DISTINCT locks.pid) FROM pg_locks locks JOIN pg_stat_activity activity ON activity.pid=locks.pid WHERE locks.locktype='advisory' AND NOT locks.granted AND activity.application_name=$1`, fixture.application).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 1 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("migration state check did not reach the coordinator")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestMigrationStateCheckWaitsForActiveRunner(t *testing.T) {
	fixture := newMigrationRunnerTestFixture(t)
	store := migrationReadOnlyStore(t, fixture)
	fixture.hold(migrationRunnerLockNamespace)
	result := startMigrationStateCheck(fixture, store, fixture.ctx, fixture.writeMigration("SELECT 1;"))
	requireMigrationStateCheckWaiting(t, fixture, result)
	if _, err := fixture.admin.Exec(fixture.ctx, "INSERT INTO "+fixture.quoted+".schema_migrations(version)VALUES('20261029000001_cleanup_probe')"); err != nil {
		t.Fatal(err)
	}
	fixture.unlock()
	select {
	case result := <-result:
		if result.err != nil || len(result.pending) != 0 {
			t.Fatal("migration check observed state from before runner completion", result.pending, result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("migration check did not resume after runner completion")
	}
	fixture.requireCounts(0, 1)
}

func TestMigrationStateCheckCancellationReleasesSession(t *testing.T) {
	fixture := newMigrationRunnerTestFixture(t)
	store := migrationReadOnlyStore(t, fixture)
	fixture.hold(migrationRunnerLockNamespace)
	ctx, cancel := context.WithCancel(fixture.ctx)
	defer cancel()
	dir := fixture.writeMigration("SELECT 1;")
	result := startMigrationStateCheck(fixture, store, ctx, dir)
	requireMigrationStateCheckWaiting(t, fixture, result)
	cancel()
	select {
	case result := <-result:
		if !errors.Is(result.err, context.Canceled) || len(result.pending) != 0 {
			t.Fatal("migration state cancellation returned partial or changed results", result.pending, result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled migration state check did not release its work")
	}
	fixture.unlock()
	if _, err := fixture.admin.Exec(fixture.ctx, "INSERT INTO "+fixture.quoted+".schema_migrations(version)VALUES('20261029000001_cleanup_probe')"); err != nil {
		t.Fatal(err)
	}
	retry, stop := context.WithTimeout(fixture.ctx, 2*time.Second)
	defer stop()
	if pending, err := fixture.stores[1].PendingMigrationVersions(retry, dir); err != nil || len(pending) != 0 {
		t.Fatal("canceled reader retained migration coordination", pending, err)
	}
	fixture.requireCounts(0, 1)
}

func TestMigrationStateReadersShareCoordinator(t *testing.T) {
	fixture := newMigrationRunnerTestFixture(t)
	store := migrationReadOnlyStore(t, fixture)
	if _, err := fixture.admin.Exec(fixture.ctx, `SELECT pg_advisory_lock_shared($1,hashtext($2))`, migrationRunnerLockNamespace, fixture.schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(fixture.ctx), 5*time.Second)
		defer cancel()
		var released bool
		if err := fixture.admin.QueryRow(cleanup, `SELECT pg_advisory_unlock_shared($1,hashtext($2))`, migrationRunnerLockNamespace, fixture.schema).Scan(&released); err != nil || !released {
			t.Error("release shared fixture lock", err)
		}
	}()
	ctx, cancel := context.WithTimeout(fixture.ctx, 2*time.Second)
	defer cancel()
	if pending, err := store.PendingMigrationVersions(ctx, fixture.writeMigration("SELECT 1;")); err != nil || len(pending) != 1 {
		t.Fatal("read-only checks serialized with another reader", pending, err)
	}
	fixture.requireCounts(0, 0)
}

func TestMigrationStateChecksAreReadOnly(t *testing.T) {
	const version = "20261029000001_cleanup_probe"
	for _, state := range []string{"missing_tracking", "existing_pending", "existing_recorded"} {
		t.Run(state, func(t *testing.T) {
			fixture := newMigrationRunnerTestFixture(t)
			dir := fixture.writeMigration("SELECT 1;")
			expectTable := state != "missing_tracking"
			if !expectTable {
				if _, err := fixture.admin.Exec(fixture.ctx, "DROP TABLE "+fixture.quoted+".schema_migrations"); err != nil {
					t.Fatal(err)
				}
			}
			want := 1
			if state == "existing_recorded" {
				if _, err := fixture.admin.Exec(fixture.ctx, "INSERT INTO "+fixture.quoted+".schema_migrations(version)VALUES($1)", version); err != nil {
					t.Fatal(err)
				}
				want = 0
			}
			store := migrationReadOnlyStore(t, fixture)
			pending, err := store.PendingMigrationVersions(fixture.ctx, dir)
			if err != nil || len(pending) != want || (want == 1 && pending[0] != version) {
				t.Fatal("read-only migration check changed the tracking contract", pending, err)
			}
			err = store.RequireNoPendingMigrations(fixture.ctx, dir)
			if (want == 0 && err != nil) || (want == 1 && (err == nil || !strings.Contains(err.Error(), "unapplied migration"))) {
				t.Fatal("startup migration requirement did not use the read-only result", err)
			}
			var exists bool
			if err := fixture.admin.QueryRow(fixture.ctx, `SELECT to_regclass($1) IS NOT NULL`, fixture.quoted+".schema_migrations").Scan(&exists); err != nil || exists != expectTable {
				t.Fatal("read-only checking created or removed migration tracking", exists, err)
			}
			if exists {
				fixture.requireCounts(0, 1-want)
			}
		})
	}
}
