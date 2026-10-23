package main

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestRunRequiresDatabaseURL(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "")
	err := run()
	if !errors.Is(err, config.ErrMissingValue) {
		t.Fatalf("err=%v, want database URL requirement", err)
	}
}

func TestMigrationDirectoryTrimsCapturedValue(t *testing.T) {
	called := false
	err := runMigrationProcess(t.Context(), migrationEnvironment(t, "EVYDENCE_DATABASE_URL=host=db", "EVYDENCE_MIGRATIONS_DIR= custom "), io.Discard, func(_ context.Context, settings config.Configuration) error {
		called = true
		if settings.Runtime().MigrationsDir != "custom" {
			t.Fatal("configured migration directory was not normalized")
		}
		return nil
	})
	if err != nil || !called {
		t.Fatal("configured migration operation was not run", err)
	}
}

func TestRunReturnsPostgresOpenFailure(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://invalid-host.invalid/evydence")
	err := run()
	if err == nil {
		t.Fatal("expected postgres open failure")
	}
}
