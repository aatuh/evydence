package wiring

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
		{name: "worker memory", config: RuntimeConfig{Process: Worker, Profile: retiredMemoryProfile, DatabaseURL: databaseURL}, want: "EVYDENCE_RUNTIME_PROFILE"},
		{name: "production snapshot load", config: RuntimeConfig{Process: API, Profile: PostgreSQL, Production: true, DatabaseURL: databaseURL, LoadMode: "snapshot_preferred"}, want: "EVYDENCE_POSTGRES_LOAD_MODE"},
		{name: "invalid secret-shaped load mode", config: RuntimeConfig{Process: API, Profile: PostgreSQL, DatabaseURL: databaseURL, LoadMode: "private-password"}, want: "EVYDENCE_POSTGRES_LOAD_MODE"},
		{name: "retired local remote object store", config: RuntimeConfig{Process: API, Profile: retiredMemoryProfile, ObjectStore: ObjectStoreConfig{Backend: "s3", SecretAccessKey: "private-s3-secret"}}, want: "retired"},
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

func TestOpenRuntimeBuildsPostgresModeWithConfiguredAdapters(t *testing.T) {
	_, pool := openHTMLReportWiringStore(t)
	discovery := &ssoDiscoveryWiringFake{}
	signer := &signingOperationWiringSigner{}
	runtime, err := OpenRuntime(t.Context(), RuntimeConfig{Process: API, Profile: PostgreSQL, DatabaseURL: pool.Config().ConnString(), MigrationsDir: "../../../migrations", SkipMigrations: true, WorkerOwnedParsers: true, ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()}, OIDC: discovery, SigningExecutor: signer})
	if err != nil || runtime == nil {
		t.Fatalf("local runtime=%#v error=%v", runtime, err)
	}
	defer runtime.Close()
	if runtime.Process != API || runtime.Production || runtime.Profile != PostgreSQL || runtime.Postgres == nil || runtime.Objects == nil || !runtime.WorkerOwnedParsers || runtime.OIDC != discovery || runtime.SigningExecutor != signer {
		t.Fatalf("PostgreSQL runtime lost configured adapters: %#v", runtime)
	}
}

func TestRetiredMemoryRuntimeDoesNotOpenFilesystemResources(t *testing.T) {
	objects := filepath.Join(t.TempDir(), "objects-must-not-be-created")
	runtime, err := OpenRuntime(t.Context(), RuntimeConfig{Process: API, Profile: retiredMemoryProfile, ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: objects}})
	if runtime != nil {
		runtime.Close()
		t.Fatal("retired profile returned an open runtime")
	}
	if err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("missing retired-profile error: %v", err)
	}
	if _, err := os.Stat(objects); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired profile touched object storage: %v", err)
	}
}

func TestOpenRuntimeRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	runtime, err := OpenRuntime(ctx, RuntimeConfig{Process: API, Profile: retiredMemoryProfile})
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
		Process: Worker, Profile: PostgreSQL, DatabaseURL: parsed.String(), WorkerOwnedParsers: true,
		MigrationsDir: "../../../migrations", ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()},
	}
	runtime, err := OpenRuntime(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Process != Worker || runtime.Production || runtime.Profile != PostgreSQL || runtime.Postgres == nil || runtime.Objects == nil || !runtime.WorkerOwnedParsers {
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
