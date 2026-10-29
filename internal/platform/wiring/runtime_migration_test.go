package wiring

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
)

func TestRuntimeProductionRejectsStartupMigrationsBeforeAdapters(t *testing.T) {
	for _, process := range []Process{API, Worker} {
		t.Run(string(process), func(t *testing.T) {
			objects := filepath.Join(t.TempDir(), "PRIVATE_OBJECTS")
			runtime, err := OpenRuntime(t.Context(), RuntimeConfig{Process: process, Profile: PostgreSQL,
				Production: true, DatabaseURL: "postgres://operator:PRIVATE_PASSWORD@127.0.0.1:1/evydence?connect_timeout=1",
				ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: objects}})
			if runtime != nil {
				runtime.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "EVYDENCE_SKIP_MIGRATIONS") || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("production startup migration policy did not fail before adapters", err)
			}
			if _, err := os.Stat(objects); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected production startup created object storage", err)
			}
		})
	}
}

func TestRuntimeMigrationFenceBlocksUntilGracefulClose(t *testing.T) {
	for _, process := range []Process{API, Worker} {
		t.Run(string(process), func(t *testing.T) {
			_, pool := openHTMLReportWiringStore(t)
			runtime, err := OpenRuntime(t.Context(), RuntimeConfig{Process: process, Profile: PostgreSQL,
				Production: true, DatabaseURL: pool.Config().ConnString(), MigrationsDir: "../../../migrations",
				SkipMigrations: true, ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()}})
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			migrator, err := postgres.Open(t.Context(), pool.Config().ConnString())
			if err != nil {
				t.Fatal(err)
			}
			defer migrator.Close()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "runtime_fence_probe.up.sql"), []byte("CREATE TABLE runtime_fence_effects(value integer NOT NULL);"), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			count, err := migrator.ApplyMigrations(ctx, dir)
			cancel()
			if count != 0 || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("migration execution overlapped an active runtime", count, err)
			}
			var changed bool
			if err := pool.QueryRow(t.Context(), `SELECT to_regclass('runtime_fence_effects') IS NOT NULL`).Scan(&changed); err != nil || changed {
				t.Fatal("blocked migration changed application schema", err)
			}
			if err := runtime.CloseContext(t.Context(), time.Second); err != nil {
				t.Fatal("graceful runtime close retained its own fence", err)
			}
			ctx, cancel = context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if count, err := migrator.ApplyMigrations(ctx, dir); err != nil || count != 1 {
				t.Fatal("closed runtime retained migration coordination", count, err)
			}
		})
	}
}

func TestRuntimeMigrationFenceRejectsInsufficientPoolBeforeDial(t *testing.T) {
	for _, tc := range []struct {
		process Process
		maximum string
	}{{API, "2"}, {Worker, "1"}} {
		t.Run(string(tc.process), func(t *testing.T) {
			runtime, err := OpenRuntime(t.Context(), RuntimeConfig{Process: tc.process, Profile: PostgreSQL,
				Production: true, SkipMigrations: true,
				DatabaseURL: "postgres://operator:PRIVATE_PASSWORD@127.0.0.1:1/evydence?connect_timeout=1&pool_max_conns=" + tc.maximum,
				ObjectStore: ObjectStoreConfig{Backend: "filesystem", Directory: t.TempDir()}})
			if runtime != nil {
				runtime.Close()
			}
			if !errors.Is(err, postgres.ErrInvalidConfiguration) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("runtime pool could starve its owned leases or reached database dialing", err)
			}
		})
	}
}
