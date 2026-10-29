package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/logging"
)

func migrationEnvironment(t *testing.T, entries ...string) config.Environment {
	t.Helper()
	e, err := config.Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestMigrationProcessUsesCapturedSettingsBeforeOperation(t *testing.T) {
	entries := []string{"EVYDENCE_DATABASE_URL=host=PRIVATE_DATABASE", "EVYDENCE_MIGRATIONS_DIR=PRIVATE_MIGRATIONS"}
	e := migrationEnvironment(t, entries...)
	entries[0] = "EVYDENCE_DATABASE_URL=PRIVATE_MUTATED"
	t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_AMBIENT")
	t.Setenv("EVYDENCE_LOG_FORMAT", "PRIVATE_AMBIENT")
	var output bytes.Buffer
	want := errors.New("PRIVATE_DATABASE_FAILURE")
	called := false
	err := runMigrationProcess(t.Context(), e, &output, func(ctx context.Context, settings config.Configuration) error {
		called = true
		if logging.FromContext(ctx) == nil || settings.Role() != config.Migrate || settings.Runtime().DatabaseURL.Reveal() != "host=PRIVATE_DATABASE" || settings.Runtime().MigrationsDir != "PRIVATE_MIGRATIONS" {
			t.Fatal("migration operation did not receive captured typed settings")
		}
		return want
	})
	if !called || !errors.Is(err, want) || strings.Contains(output.String(), "PRIVATE") || strings.Count(output.String(), "\n") != 2 || !strings.Contains(output.String(), `"result_code":"failed"`) {
		t.Fatal("migration lifecycle lost the result or exposed configuration/driver errors")
	}
}

func TestMigrationProcessRejectsInputBeforeOperation(t *testing.T) {
	for _, tc := range []struct {
		entries []string
		want    error
	}{
		{nil, config.ErrMissingValue},
		{[]string{"EVYDENCE_DATABASE_URL=PRIVATE_INVALID"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_DATABASE_URL=host=db", "EVYDENCE_LOG_FORMAT=PRIVATE_INVALID"}, config.ErrInvalidValue},
		{[]string{"EVYDENCE_DATABASE_URL=host=db", "EVYDENCE_MIGRATIONS_DIR=PRIVATE\nPATH"}, config.ErrInvalidValue},
		{[]string{"ENV=production", "EVYDENCE_DATABASE_URL=host=db", "EVYDENCE_PRIVATE_UNKNOWN=PRIVATE_VALUE"}, config.ErrUnknownOption},
	} {
		var output bytes.Buffer
		called := false
		err := runMigrationProcess(t.Context(), migrationEnvironment(t, tc.entries...), &output, func(context.Context, config.Configuration) error { called = true; return nil })
		if !errors.Is(err, tc.want) || called || strings.Contains(output.String()+err.Error(), "PRIVATE") || strings.Contains(output.String(), `"result_code":"started"`) || !strings.Contains(output.String(), `"result_code":"rejected"`) || strings.Count(output.String(), "\n") != 1 {
			t.Fatal("invalid configuration reached migration startup or disclosed input", err)
		}
	}
}

func TestMigrationProcessUsesSchemaDefaultDirectory(t *testing.T) {
	var output bytes.Buffer
	called := false
	err := runMigrationProcess(t.Context(), migrationEnvironment(t, "EVYDENCE_DATABASE_URL=host=db"), &output, func(_ context.Context, settings config.Configuration) error {
		called = true
		if settings.Runtime().MigrationsDir != "migrations" || settings.Runtime().MigrationTimeout != 30*time.Second {
			t.Fatal("migration command did not use its schema-owned default")
		}
		return nil
	})
	if err != nil || !called || !strings.Contains(output.String(), `"result_code":"succeeded"`) {
		t.Fatal("migration operation was not run", err)
	}
}

func TestMigrationProcessRejectsCancellationBeforeOperation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var output bytes.Buffer
	called := false
	err := runMigrationProcess(ctx, migrationEnvironment(t, "EVYDENCE_DATABASE_URL=host=db"), &output, func(context.Context, config.Configuration) error { called = true; return nil })
	if !errors.Is(err, context.Canceled) || called || strings.Contains(output.String(), `"result_code":"started"`) || !strings.Contains(output.String(), `"result_code":"rejected"`) {
		t.Fatal("cancelled migration started an operation", err)
	}
}

func TestMigrationProcessRejectsInvalidPlanSettingsBeforeOperation(t *testing.T) {
	for _, entries := range [][]string{
		{"EVYDENCE_MIGRATION_TARGET=PRIVATE_TARGET"},
		{"EVYDENCE_MIGRATION_CHECKSUMS_FILE=PRIVATE_CHECKSUMS"},
		{"EVYDENCE_MIGRATION_TIMEOUT_SECONDS=0"},
		{"EVYDENCE_MIGRATION_TIMEOUT_SECONDS=901"},
		{"EVYDENCE_MIGRATION_TIMEOUT_SECONDS=PRIVATE_TIMEOUT"},
		{"EVYDENCE_MIGRATION_TARGET=a", "EVYDENCE_MIGRATION_CHECKSUMS_FILE=PRIVATE\nPATH"},
		{"EVYDENCE_MIGRATION_TARGET=PRIVATE\nTARGET", "EVYDENCE_MIGRATION_CHECKSUMS_FILE=checksums"},
		{"EVYDENCE_MIGRATION_TARGET=../PRIVATE_TARGET", "EVYDENCE_MIGRATION_CHECKSUMS_FILE=checksums"},
	} {
		entries = append(entries, "EVYDENCE_DATABASE_URL=host=db")
		var output bytes.Buffer
		called := false
		err := runMigrationProcess(t.Context(), migrationEnvironment(t, entries...), &output, func(context.Context, config.Configuration) error { called = true; return nil })
		if !errors.Is(err, config.ErrInvalidValue) || called || strings.Contains(output.String(), "PRIVATE") || strings.Contains(output.String(), `"result_code":"started"`) {
			t.Fatal("invalid migration plan settings reached the operation or exposed input", err)
		}
	}
}

func TestMigrationProcessCapturesTypedPlanSettings(t *testing.T) {
	for _, production := range []bool{false, true} {
		entries := []string{"EVYDENCE_DATABASE_URL=host=db", "EVYDENCE_MIGRATION_TARGET= b ", "EVYDENCE_MIGRATION_CHECKSUMS_FILE= checksums ", "EVYDENCE_MIGRATION_TIMEOUT_SECONDS=900"}
		if production {
			entries = append(entries, "ENV=production")
		}
		called := false
		err := runMigrationProcess(t.Context(), migrationEnvironment(t, entries...), &bytes.Buffer{}, func(_ context.Context, settings config.Configuration) error {
			called = true
			runtime := settings.Runtime()
			if runtime.MigrationTarget != "b" || runtime.MigrationChecksumsFile != "checksums" || runtime.MigrationTimeout != 900*time.Second {
				t.Fatal("migration operation lost normalized captured plan settings")
			}
			return nil
		})
		if err != nil || !called {
			t.Fatal("migration plan settings were rejected or not projected", err)
		}
	}
}
