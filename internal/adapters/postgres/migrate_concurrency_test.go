package postgres

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestConcurrentMigrationSessionsApplyEachVersionOnce(t *testing.T) {
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
	quoted := pgx.Identifier{schema}.Sanitize()
	application := "migration-race-" + schema
	const barrierNamespace int32 = 0x65767974
	var stores []*Store
	var workers sync.WaitGroup
	created, locked := false, false
	t.Cleanup(func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer stop()
		if locked {
			if _, err := admin.Exec(cleanup, `SELECT pg_advisory_unlock($1,hashtext($2))`, barrierNamespace, schema); err != nil {
				t.Error("release migration test barrier", err)
			}
		}
		workers.Wait()
		for _, store := range stores {
			store.Close()
		}
		if created {
			if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
				t.Error("remove migration test schema", err)
			}
		}
		if err := admin.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	created = true
	// Precreate the version table so the regression isolates duplicate execution,
	// rather than the separate race in bootstrap CREATE TABLE IF NOT EXISTS.
	if _, err := admin.Exec(ctx, "CREATE TABLE "+quoted+`.schema_migrations(version text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now()); CREATE TABLE `+quoted+`.migration_effects(value integer NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		config, err := pgxpool.ParseConfig(databaseURLWithSearchPath(t, databaseURL, schema))
		if err != nil {
			t.Fatal(err)
		}
		config.MaxConns, config.MinConns, config.MinIdleConns = 1, 0, 0
		config.ConnConfig.RuntimeParams["application_name"] = application
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		stores = append(stores, &Store{pool: pool})
	}
	if _, err := admin.Exec(ctx, `SELECT pg_advisory_lock($1,hashtext($2))`, barrierNamespace, schema); err != nil {
		t.Fatal(err)
	}
	locked = true
	dir := t.TempDir()
	body := fmt.Sprintf("SELECT pg_advisory_xact_lock(%d,hashtext(current_schema())); INSERT INTO migration_effects(value) VALUES(1);", barrierNamespace)
	if err := os.WriteFile(filepath.Join(dir, "20261029000001_runner_probe.up.sql"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	type result struct {
		count int
		err   error
	}
	results := make(chan result, 2)
	for _, store := range stores {
		workers.Add(1)
		go func() {
			defer workers.Done()
			count, err := store.ApplyMigrations(ctx, dir)
			results <- result{count, err}
		}()
	}
	// Old code has both sessions waiting inside the SQL body. A coordinated
	// runner has one there and the other waiting for the runner lock. Requiring
	// two database waiters rules out a process-local mutex and scheduling sleeps.
	wait, stopWait := context.WithTimeout(ctx, 5*time.Second)
	defer stopWait()
	for {
		var waiting int
		if err := admin.QueryRow(wait, `SELECT count(DISTINCT locks.pid) FROM pg_locks locks JOIN pg_stat_activity activity ON activity.pid=locks.pid WHERE locks.locktype='advisory' AND NOT locks.granted AND activity.application_name=$1`, application).Scan(&waiting); err != nil {
			t.Fatal("both migration sessions did not reach database lock waits", err)
		}
		if waiting == 2 {
			break
		}
		select {
		case <-wait.Done():
			t.Fatal("both migration sessions did not reach database lock waits")
		case <-time.After(5 * time.Millisecond):
		}
	}
	var released bool
	if err := admin.QueryRow(ctx, `SELECT pg_advisory_unlock($1,hashtext($2))`, barrierNamespace, schema).Scan(&released); err != nil || !released {
		t.Fatal("release deterministic migration barrier", err)
	}
	locked = false
	applied := 0
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatal("concurrent migration runner failed", result.err)
			}
			applied += result.count
		case <-ctx.Done():
			t.Fatal("concurrent migration runners did not finish", ctx.Err())
		}
	}
	var effects, versions int
	if err := admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM "+quoted+`.migration_effects),(SELECT count(*) FROM `+quoted+`.schema_migrations)`).Scan(&effects, &versions); err != nil {
		t.Fatal(err)
	}
	if applied != 1 || effects != 1 || versions != 1 {
		t.Fatalf("concurrent sessions duplicated a migration: applied=%d effects=%d versions=%d", applied, effects, versions)
	}
	for _, store := range stores {
		if store.pool.Stat().AcquiredConns() != 0 {
			t.Fatal("migration runner retained its only pool connection")
		}
	}
}
