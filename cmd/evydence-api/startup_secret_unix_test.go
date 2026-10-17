//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/config"
)

func TestAPIProcessResolvesPrivateDatabaseAndPepperBeforeProviders(t *testing.T) {
	directory := t.TempDir()
	database, pepper := filepath.Join(directory, "PRIVATE_DSN"), filepath.Join(directory, "PRIVATE_PEPPER")
	for name, value := range map[string]string{database: "host=PRIVATE_DB sslmode=disable\n", pepper: "PRIVATE_FILE_PEPPER\n"} {
		if err := os.WriteFile(name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	e := apiCapturedEnvironment(t, "EVYDENCE_DATABASE_URL=", "EVYDENCE_DATABASE_URL_FILE="+database, "EVYDENCE_API_KEY_PEPPER=", "EVYDENCE_API_KEY_PEPPER_FILE="+pepper)
	t.Setenv("PGSERVICE", "")
	var output bytes.Buffer
	called := false
	err := runAPIProcess(t.Context(), e, &output, func(_ context.Context, settings config.Configuration, prepared postgres.PreparedPoolConfig) error {
		called = true
		if settings.API().KeyPepper.Reveal() != "PRIVATE_FILE_PEPPER" || !prepared.Matches("host=PRIVATE_DB sslmode=disable") {
			t.Fatal("API entered providers with unresolved private-file values")
		}
		return nil
	})
	if err != nil || !called || strings.Contains(output.String(), "PRIVATE") {
		t.Fatal("private API files failed or leaked input", err)
	}
	for _, public := range []string{database, pepper} {
		if err := os.Chmod(public, 0644); err != nil {
			t.Fatal(err)
		}
		called = false
		output.Reset()
		err := runAPIProcess(t.Context(), e, &output, func(context.Context, config.Configuration, postgres.PreparedPoolConfig) error {
			called = true
			return nil
		})
		if called || !errors.Is(err, config.ErrSecretResolution) || strings.Contains(output.String(), "PRIVATE") {
			t.Fatal("unsafe private-file permissions reached API providers", err)
		}
		if err := os.Chmod(public, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
