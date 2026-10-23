package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

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
		if settings.Runtime().MigrationsDir != "migrations" {
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
