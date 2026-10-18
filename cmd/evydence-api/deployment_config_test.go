//go:build deployment

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/deploymentcheck"
)

func TestDeploymentAPIStartup(t *testing.T) {
	for _, source := range deploymentcheck.ServerSources {
		t.Run(source.Name+"-"+source.Mode, func(t *testing.T) {
			fixture := deploymentcheck.Load(t, source.Name, "api", source.Mode)
			environment := fixture.Input(t, nil)
			t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_CHANGED_AFTER_CAPTURE")
			t.Setenv("EVYDENCE_API_KEY_PEPPER", "PRIVATE_CHANGED_AFTER_CAPTURE")
			t.Setenv("PGSERVICE", "")
			var output bytes.Buffer
			called := false
			err := runAPIProcess(t.Context(), environment, &output, func(_ context.Context, settings config.Configuration, database postgres.PreparedPoolConfig) error {
				called = true
				if !settings.Production() || settings.Role() != config.API || settings.Runtime().Profile != "postgres" || settings.Runtime().PostgresLoadMode != "relational_only" || !database.IsPrepared() || !database.Matches(fixture.Expected["EVYDENCE_DATABASE_URL"]) || settings.API().KeyPepper.Reveal() != fixture.Expected["EVYDENCE_API_KEY_PEPPER"] || settings.Storage().S3AccessKeyID.Reveal() != fixture.Expected["EVYDENCE_S3_ACCESS_KEY_ID"] || settings.Storage().S3SecretAccessKey.Reveal() != fixture.Expected["EVYDENCE_S3_SECRET_ACCESS_KEY"] || settings.Providers().SigningExecutorToken.Reveal() != fixture.Expected["EVYDENCE_SIGNING_EXECUTOR_TOKEN"] {
					t.Fatal("rendered API settings were not preserved through startup")
				}
				return nil
			})
			if err != nil || !called {
				t.Fatal("rendered API did not reach validated startup")
			}
			fixture.CheckDiagnostics(t, output.String(), err)
			t.Run("actual-command-preflight", func(t *testing.T) {
				fixture.Install(t, os.Environ(), map[string]string{"EVYDENCE_HTTP_READ_TIMEOUT_SECONDS": "0"})
				ctx, cancel := context.WithCancel(t.Context())
				cancel() // Keeps any regressed post-preflight startup inert.
				err := runWithContext(ctx)
				if !errors.Is(err, config.ErrInvalidValue) {
					t.Fatal("actual API command did not reject invalid captured configuration")
				}
				fixture.CheckDiagnostics(t, "", err)
			})
			conflictOption, conflictValue := "EVYDENCE_DATABASE_URL_FILE", "/PRIVATE_ABSENT/file"
			if source.Mode == "files" {
				conflictOption, conflictValue = "EVYDENCE_DATABASE_URL", fixture.Expected["EVYDENCE_DATABASE_URL"]
			}
			for _, invalid := range []struct {
				name, option, value string
				want                error
			}{
				{"timeout", "EVYDENCE_HTTP_READ_TIMEOUT_SECONDS", "0", config.ErrInvalidValue},
				{"unknown", "EVYDENCE_PRIVATE_UNKNOWN", "PRIVATE_VALUE", config.ErrUnknownOption},
				{"printing", "EVYDENCE_PRINT_BOOTSTRAP_SECRET", "true", config.ErrUnsafeProduction},
				{"insecure", "EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST", "true", config.ErrUnsafeProduction},
				{"source-conflict", conflictOption, conflictValue, config.ErrConflictingSecretSources},
			} {
				t.Run(invalid.name, func(t *testing.T) {
					output.Reset()
					called = false
					err := runAPIProcess(t.Context(), fixture.Input(t, map[string]string{invalid.option: invalid.value}), &output, func(context.Context, config.Configuration, postgres.PreparedPoolConfig) error {
						called = true
						return nil
					})
					if !errors.Is(err, invalid.want) || called {
						t.Fatal("invalid rendered API configuration reached startup")
					}
					fixture.CheckDiagnostics(t, output.String(), err)
				})
			}
			if source.Mode == "files" {
				t.Run("malformed-file", func(t *testing.T) {
					fixture.SetFileContents(t, "EVYDENCE_DATABASE_URL_FILE", "PRIVATE_INVALID_DSN")
					output.Reset()
					called = false
					err := runAPIProcess(t.Context(), fixture.Input(t, nil), &output, func(context.Context, config.Configuration, postgres.PreparedPoolConfig) error {
						called = true
						return nil
					})
					if !errors.Is(err, config.ErrSecretResolution) || called {
						t.Fatal("malformed loaded DSN reached API startup")
					}
					fixture.CheckDiagnostics(t, output.String(), err)
				})
				t.Run("public-file", func(t *testing.T) {
					fixture.SetFileMode(t, "EVYDENCE_DATABASE_URL_FILE", 0o644)
					output.Reset()
					called = false
					err := runAPIProcess(t.Context(), fixture.Input(t, nil), &output, func(context.Context, config.Configuration, postgres.PreparedPoolConfig) error {
						called = true
						return nil
					})
					if !errors.Is(err, config.ErrSecretResolution) || called {
						t.Fatal("unsafe rendered file reached API startup")
					}
					fixture.CheckDiagnostics(t, output.String(), err)
				})
			}
		})
	}
}
