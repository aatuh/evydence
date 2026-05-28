package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigrationCompatibilityFromEveryCommittedState(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if strings.TrimSpace(databaseURL) == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	names := migrationFileNames(t, "../../../migrations")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	basePool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer basePool.Close()

	for prefix := 0; prefix <= len(names); prefix++ {
		prefix := prefix
		t.Run(fmt.Sprintf("prefix_%02d", prefix), func(t *testing.T) {
			schema := fmt.Sprintf("evydence_migration_%d_%02d", time.Now().UnixNano(), prefix)
			quotedSchema := pgx.Identifier{schema}.Sanitize()
			if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
				t.Fatal(err)
			}
			defer func(cleanupCtx context.Context) {
				_, _ = basePool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
			}(context.WithoutCancel(ctx))

			store, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, schema))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			applyMigrationPrefix(t, ctx, store, "../../../migrations", names[:prefix])
			applied, err := store.ApplyMigrations(ctx, "../../../migrations")
			if err != nil {
				t.Fatalf("upgrade from prefix %d: %v", prefix, err)
			}
			if want := len(names) - prefix; applied != want {
				t.Fatalf("applied migrations = %d, want %d", applied, want)
			}
			var count int
			if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != len(names) {
				t.Fatalf("schema_migrations count = %d, want %d", count, len(names))
			}
			again, err := store.ApplyMigrations(ctx, "../../../migrations")
			if err != nil {
				t.Fatalf("idempotent apply from prefix %d: %v", prefix, err)
			}
			if again != 0 {
				t.Fatalf("second apply = %d, want 0", again)
			}
			for _, table := range []string{"ledger_state", "resource_index", "outbox_jobs", "schema_migrations"} {
				var exists bool
				err := store.pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists)
				if err != nil {
					t.Fatal(err)
				}
				if !exists {
					t.Fatalf("table %s is missing after migration upgrade", table)
				}
			}
		})
	}
}

func migrationFileNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no migration files found")
	}
	return names
}

func applyMigrationPrefix(t *testing.T, ctx context.Context, store *Store, dir string, names []string) {
	t.Helper()
	if _, err := store.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		version := strings.TrimSuffix(name, ".up.sql")
		body, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- migration names come from ReadDir and are filtered to .up.sql files.
		if err != nil {
			t.Fatal(err)
		}
		tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("apply prefix migration %s: %v", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("record prefix migration %s: %v", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func databaseURLWithSearchPath(t *testing.T, rawURL, schema string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
