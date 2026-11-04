package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestMigrationProcessCapturesManagedRuntimeRole(t *testing.T) {
	environment := migrationEnvironment(t, "ENV=production", "EVYDENCE_DATABASE_URL=host=PRIVATE_DATABASE", "EVYDENCE_MIGRATION_TARGET=a", "EVYDENCE_MIGRATION_CHECKSUMS_FILE=PRIVATE_CHECKSUMS", "EVYDENCE_MIGRATION_RUNTIME_ROLE=PRIVATE_RUNTIME")
	t.Setenv("EVYDENCE_MIGRATION_RUNTIME_ROLE", "PRIVATE_CHANGED")
	var output bytes.Buffer
	called := false
	err := runMigrationProcess(t.Context(), environment, &output, func(_ context.Context, settings config.Configuration) error {
		called = true
		if settings.Runtime().MigrationRuntimeRole != "PRIVATE_RUNTIME" {
			t.Fatal("managed runtime role was not captured in typed settings")
		}
		return nil
	})
	if err != nil || !called || strings.Contains(output.String(), "PRIVATE") {
		t.Fatal("managed role configuration failed or leaked its input", err)
	}
}

func TestMigrationProcessRejectsInvalidManagedRoleBeforeOperation(t *testing.T) {
	for _, role := range []string{"PRIVATE\nROLE", strings.Repeat("a", 64), "   "} {
		var output bytes.Buffer
		called := false
		err := runMigrationProcess(t.Context(), migrationEnvironment(t, "EVYDENCE_DATABASE_URL=host=PRIVATE_DATABASE", "EVYDENCE_MIGRATION_TARGET=a", "EVYDENCE_MIGRATION_CHECKSUMS_FILE=PRIVATE_CHECKSUMS", "EVYDENCE_MIGRATION_RUNTIME_ROLE="+role), &output, func(context.Context, config.Configuration) error { called = true; return nil })
		if err == nil || called || strings.Contains(output.String(), "PRIVATE") {
			t.Fatal("invalid managed role reached an operation or leaked input")
		}
	}
	var output bytes.Buffer
	called := false
	err := runMigrationProcess(t.Context(), migrationEnvironment(t, "EVYDENCE_DATABASE_URL=host=PRIVATE_DATABASE", "EVYDENCE_MIGRATION_RUNTIME_ROLE=PRIVATE_RUNTIME"), &output, func(context.Context, config.Configuration) error { called = true; return nil })
	if called || !errors.Is(err, config.ErrInvalidValue) {
		t.Fatal("managed role was accepted without verified target/checksum inputs", err)
	}
}

func TestMigrationCaptureRejectsInvalidManagedRoleEncoding(t *testing.T) {
	_, err := config.Capture([]string{"EVYDENCE_MIGRATION_RUNTIME_ROLE=" + string([]byte{0xff})})
	if !errors.Is(err, config.ErrInvalidEnvironment) {
		t.Fatal("invalid managed-role encoding survived environment capture")
	}
}
