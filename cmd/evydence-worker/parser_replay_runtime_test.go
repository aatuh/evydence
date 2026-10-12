package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

func TestRunParserReplayUsesSharedRuntimeWithLivePostgres(t *testing.T) {
	baseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	schema := "evydence_replay_runtime_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		_, _ = admin.Exec(dropCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}()
	databaseURL := postgresURLWithSearchPath(t, baseURL, schema)
	t.Setenv("ENV", "")
	t.Setenv("EVYDENCE_DATABASE_URL", databaseURL)
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "postgres")
	t.Setenv("EVYDENCE_POSTGRES_LOAD_MODE", "relational_only")
	t.Setenv("EVYDENCE_MIGRATIONS_DIR", "../../migrations")
	t.Setenv("EVYDENCE_SKIP_MIGRATIONS", "")
	t.Setenv("EVYDENCE_OBJECT_STORE", "filesystem")
	t.Setenv("EVYDENCE_OBJECT_DIR", t.TempDir())
	args := []string{"--tenant", "ten_missing", "--evidence", "ev_missing", "--parser-version", app.ParserVersionSPDXJSON, "--actor", "operator", "--apply"}
	if err := runParserReplay(args); err == nil || !strings.Contains(err.Error(), "source evidence not found") {
		t.Fatalf("parser replay did not reach the empty durable state: %v", err)
	}
	store, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.RequireNoPendingMigrations(ctx, "../../migrations"); err != nil {
		t.Fatalf("shared runtime did not apply migrations: %v", err)
	}
}
