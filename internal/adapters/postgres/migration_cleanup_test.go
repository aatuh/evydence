package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationCleanupBarrierNamespace int32 = 0x65767975

type migrationRunnerTestResult struct {
	count int
	err   error
}

type migrationRunnerTestFixture struct {
	t           *testing.T
	ctx         context.Context
	cancel      context.CancelFunc
	admin       *pgx.Conn
	schema      string
	quoted      string
	application string
	stores      []*Store
	workers     sync.WaitGroup
	held        bool
	namespace   int32
}

func newMigrationRunnerTestFixture(t *testing.T) *migrationRunnerTestFixture {
	t.Helper()
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	admin, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	schema := "evydence_migration_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	f := &migrationRunnerTestFixture{t: t, ctx: ctx, cancel: cancel, admin: admin,
		schema: schema, quoted: pgx.Identifier{schema}.Sanitize(), application: "migration-test-" + schema}
	created := false
	t.Cleanup(func() {
		f.cancel()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer stop()
		if f.held {
			if _, err := admin.Exec(cleanup, `SELECT pg_advisory_unlock($1,hashtext($2))`, f.namespace, schema); err != nil {
				t.Error(err)
			}
		}
		f.workers.Wait()
		for _, store := range f.stores {
			store.Close()
		}
		if created {
			if _, err := admin.Exec(cleanup, "DROP SCHEMA "+f.quoted+" CASCADE"); err != nil {
				t.Error(err)
			}
		}
		if err := admin.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+f.quoted); err != nil {
		t.Fatal(err)
	}
	created = true
	if _, err := admin.Exec(ctx, "CREATE TABLE "+f.quoted+`.schema_migrations(version text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now()); CREATE TABLE `+f.quoted+`.migration_effects(value integer NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		config, err := pgxpool.ParseConfig(databaseURLWithSearchPath(t, databaseURL, schema))
		if err != nil {
			t.Fatal(err)
		}
		config.MaxConns, config.MinConns, config.MinIdleConns = 1, 0, 0
		config.ConnConfig.RuntimeParams["application_name"] = f.application
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		f.stores = append(f.stores, &Store{pool: pool})
	}
	return f
}

func (f *migrationRunnerTestFixture) writeMigration(body string) string {
	f.t.Helper()
	dir := f.t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "20261029000001_cleanup_probe.up.sql"), []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return dir
}

func (f *migrationRunnerTestFixture) hold(namespace int32) {
	f.t.Helper()
	if _, err := f.admin.Exec(f.ctx, `SELECT pg_advisory_lock($1,hashtext($2))`, namespace, f.schema); err != nil {
		f.t.Fatal(err)
	}
	f.namespace, f.held = namespace, true
}

func (f *migrationRunnerTestFixture) unlock() {
	f.t.Helper()
	var released bool
	if err := f.admin.QueryRow(f.ctx, `SELECT pg_advisory_unlock($1,hashtext($2))`, f.namespace, f.schema).Scan(&released); err != nil || !released {
		f.t.Fatal("release migration fixture lock", err)
	}
	f.held = false
}

func (f *migrationRunnerTestFixture) start(ctx context.Context, dir string) <-chan migrationRunnerTestResult {
	f.t.Helper()
	result := make(chan migrationRunnerTestResult, 1)
	f.workers.Add(1)
	go func() {
		defer f.workers.Done()
		count, err := f.stores[0].ApplyMigrations(ctx, dir)
		result <- migrationRunnerTestResult{count, err}
	}()
	return result
}

func (f *migrationRunnerTestFixture) waitForDatabaseWaiter() {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	for {
		var waiting int
		if err := f.admin.QueryRow(ctx, `SELECT count(DISTINCT locks.pid) FROM pg_locks locks JOIN pg_stat_activity activity ON activity.pid=locks.pid WHERE locks.locktype='advisory' AND NOT locks.granted AND activity.application_name=$1`, f.application).Scan(&waiting); err != nil {
			f.t.Fatal("migration did not reach the database wait", err)
		}
		if waiting == 1 {
			return
		}
		select {
		case <-ctx.Done():
			f.t.Fatal("migration did not reach the database wait")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (f *migrationRunnerTestFixture) requireCounts(effects, versions int) {
	f.t.Helper()
	var actualEffects, actualVersions int
	if err := f.admin.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM "+f.quoted+`.migration_effects),(SELECT count(*) FROM `+f.quoted+`.schema_migrations)`).Scan(&actualEffects, &actualVersions); err != nil || effects != actualEffects || versions != actualVersions {
		f.t.Fatalf("migration effects=%d versions=%d, want %d/%d: %v", actualEffects, actualVersions, effects, versions, err)
	}
}

func (f *migrationRunnerTestFixture) requireRetryOnOtherSession() {
	f.t.Helper()
	dir := f.writeMigration("INSERT INTO migration_effects(value) VALUES(1);")
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	if count, err := f.stores[1].ApplyMigrations(ctx, dir); err != nil || count != 1 {
		f.t.Fatal("migration lock or transaction survived failure/cancellation", count, err)
	}
	f.requireCounts(1, 1)
}

func TestMigrationRunnerReleasesAfterSQLFailure(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	dir := f.writeMigration("INSERT INTO migration_effects(value) VALUES(1); SELECT 1/0;")
	count, err := f.stores[0].ApplyMigrations(f.ctx, dir)
	var databaseError *pgconn.PgError
	if count != 0 || !errors.As(err, &databaseError) || databaseError.Code != "22012" {
		t.Fatal("migration did not preserve its actual SQL failure", count, err)
	}
	f.requireCounts(0, 0)
	f.requireRetryOnOtherSession()
}

func TestMigrationRunnerCancellationReleasesOwnedSession(t *testing.T) {
	for _, phase := range []string{"waiting_for_runner", "executing_sql"} {
		t.Run(phase, func(t *testing.T) {
			f := newMigrationRunnerTestFixture(t)
			body := "INSERT INTO migration_effects(value) VALUES(1);"
			if phase == "waiting_for_runner" {
				f.hold(migrationRunnerLockNamespace)
			} else {
				f.hold(migrationCleanupBarrierNamespace)
				body += fmt.Sprintf(" SELECT pg_advisory_xact_lock(%d,hashtext(current_schema()));", migrationCleanupBarrierNamespace)
			}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			result := f.start(ctx, f.writeMigration(body))
			f.waitForDatabaseWaiter()
			cancel()
			select {
			case result := <-result:
				if result.count != 0 || !errors.Is(result.err, context.Canceled) {
					t.Fatal("migration cancellation lost its outcome", result.count, result.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled migration did not release its owned work")
			}
			f.requireCounts(0, 0)
			f.unlock()
			f.requireRetryOnOtherSession()
		})
	}
}

func TestMigrationRunnerDiscardsSessionWhenUnlockIsUncertain(t *testing.T) {
	f := newMigrationRunnerTestFixture(t)
	var before int32
	if err := f.stores[0].pool.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("SELECT pg_advisory_unlock(%d,hashtext(current_schema())); INSERT INTO migration_effects(value) VALUES(1);", migrationRunnerLockNamespace)
	count, err := f.stores[0].ApplyMigrations(f.ctx, f.writeMigration(body))
	if count != 1 || err == nil {
		t.Fatal("lost lock ownership was silently accepted", count, err)
	}
	f.requireCounts(1, 1)
	var after int32
	if err := f.stores[0].pool.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&after); err != nil || before == after {
		t.Fatal("uncertain migration session returned to the pool", err)
	}
}
