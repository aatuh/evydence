package wiring

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOpenRuntimeRejectsUnsafeConfigurationBeforeOpeningAdapters(t *testing.T) {
	const databaseURL = "postgres://operator:private-password@127.0.0.1:1/evydence?connect_timeout=1"
	tests := []struct {
		name   string
		config RuntimeConfig
		want   string
	}{
		{name: "worker memory", config: RuntimeConfig{Process: Worker, Profile: LocalMemory, DatabaseURL: databaseURL}, want: "EVYDENCE_RUNTIME_PROFILE"},
		{name: "production snapshot load", config: RuntimeConfig{Process: API, Profile: PostgreSQL, Production: true, DatabaseURL: databaseURL, LoadMode: "snapshot_preferred"}, want: "EVYDENCE_POSTGRES_LOAD_MODE"},
		{name: "invalid secret-shaped load mode", config: RuntimeConfig{Process: API, Profile: PostgreSQL, DatabaseURL: databaseURL, LoadMode: "private-password"}, want: "EVYDENCE_POSTGRES_LOAD_MODE"},
		{name: "local remote object store", config: RuntimeConfig{Process: API, Profile: LocalMemory, ObjectStore: ObjectStoreConfig{Backend: "s3", SecretAccessKey: "private-s3-secret"}}, want: "EVYDENCE_OBJECT_STORE=filesystem"},
		{name: "unknown object store", config: RuntimeConfig{Process: Worker, Profile: PostgreSQL, DatabaseURL: databaseURL, ObjectStore: ObjectStoreConfig{Backend: "unknown"}}, want: "EVYDENCE_OBJECT_STORE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, err := OpenRuntime(t.Context(), test.config)
			if err == nil || runtime != nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe runtime=%#v error=%v, want %q", runtime, err, test.want)
			}
			if strings.Contains(err.Error(), "private-password") || strings.Contains(err.Error(), "private-s3-secret") {
				t.Fatalf("runtime error leaked credentials: %v", err)
			}
		})
	}
}

func TestOpenRuntimeBuildsExplicitLocalMemoryMode(t *testing.T) {
	runtime, err := OpenRuntime(t.Context(), RuntimeConfig{Process: API, Profile: LocalMemory, ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()}})
	if err != nil || runtime == nil {
		t.Fatalf("local runtime=%#v error=%v", runtime, err)
	}
	defer runtime.Close()
	if runtime.Profile != LocalMemory || runtime.Postgres != nil || runtime.Objects == nil || len(runtime.Profile.Limitations()) == 0 {
		t.Fatalf("local runtime did not retain explicit limitations: %#v", runtime)
	}
}

func TestOpenRuntimeRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	runtime, err := OpenRuntime(ctx, RuntimeConfig{Process: API, Profile: LocalMemory})
	if runtime != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled runtime=%#v error=%v", runtime, err)
	}
}

func TestRuntimeAdapterErrorPreservesCancellationWithoutLeakingCredentials(t *testing.T) {
	cause := fmt.Errorf("postgres://operator:private-password@database.example.test/evydence: %w", context.DeadlineExceeded)
	err := runtimeAdapterError("open PostgreSQL runtime", cause)
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "private-password") {
		t.Fatalf("unsafe cancellation error: %v", err)
	}
	err = runtimeAdapterError("open PostgreSQL runtime", errors.New("postgres://operator:private-password@database.example.test/evydence unavailable"))
	if err == nil || strings.Contains(err.Error(), "private-password") || !strings.Contains(err.Error(), "open PostgreSQL runtime") {
		t.Fatalf("unsafe adapter error: %v", err)
	}
}

func TestOpenRuntimeSharesPostgresMigrationAndObjectRules(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("evydence_wiring_runtime_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		_, _ = admin.Exec(dropCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}()
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	params := parsed.Query()
	params.Set("search_path", schema)
	parsed.RawQuery = params.Encode()
	config := RuntimeConfig{
		Process: Worker, Profile: PostgreSQL, DatabaseURL: parsed.String(),
		MigrationsDir: "../../../migrations", ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()},
	}
	runtime, err := OpenRuntime(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Profile != PostgreSQL || runtime.Postgres == nil || runtime.Objects == nil {
		t.Fatalf("incomplete durable runtime: %#v", runtime)
	}
	if err := runtime.Postgres.CheckMigrationState(ctx, config.MigrationsDir); err != nil {
		t.Fatalf("runtime migrations: %v", err)
	}
	runtime.Close()
	runtime.Close()
	config.SkipMigrations = true
	checked, err := OpenRuntime(ctx, config)
	if err != nil {
		t.Fatalf("check existing migrations: %v", err)
	}
	checked.Close()
}
