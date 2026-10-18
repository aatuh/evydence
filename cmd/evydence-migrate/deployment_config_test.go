//go:build deployment

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/deploymentcheck"
)

func TestDeploymentMigrationStartup(t *testing.T) {
	for _, mode := range []string{"env", "files"} {
		t.Run(mode, func(t *testing.T) {
			fixture := deploymentcheck.Load(t, "compose", "migrate", mode)
			environment := fixture.Input(t, nil)
			t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_CHANGED_AFTER_CAPTURE")
			var output bytes.Buffer
			called := false
			err := runMigrationProcess(t.Context(), environment, &output, func(_ context.Context, settings config.Configuration) error {
				called = true
				if !settings.Production() || settings.Role() != config.Migrate || settings.Runtime().DatabaseURL.Reveal() != fixture.Expected["EVYDENCE_DATABASE_URL"] || settings.Runtime().MigrationsDir != "migrations" {
					t.Fatal("rendered migration settings were not preserved")
				}
				return nil
			})
			if err != nil || !called {
				t.Fatal("rendered migration did not reach validated startup")
			}
			fixture.CheckDiagnostics(t, output.String(), err)
			output.Reset()
			called = false
			err = runMigrationProcess(t.Context(), fixture.Input(t, map[string]string{"EVYDENCE_PRIVATE_UNKNOWN": "PRIVATE_VALUE"}), &output, func(context.Context, config.Configuration) error { called = true; return nil })
			if !errors.Is(err, config.ErrUnknownOption) || called {
				t.Fatal("unknown rendered migration setting reached an operation")
			}
			fixture.CheckDiagnostics(t, output.String(), err)
			if mode == "files" {
				t.Run("malformed-file", func(t *testing.T) {
					fixture.SetFileContents(t, "EVYDENCE_DATABASE_URL_FILE", "PRIVATE_INVALID_DSN")
					output.Reset()
					called = false
					err := runMigrationProcess(t.Context(), fixture.Input(t, nil), &output, func(context.Context, config.Configuration) error { called = true; return nil })
					if !errors.Is(err, config.ErrSecretResolution) || called {
						t.Fatal("malformed loaded DSN reached a migration operation")
					}
					fixture.CheckDiagnostics(t, output.String(), err)
				})
				fixture.SetFileMode(t, "EVYDENCE_DATABASE_URL_FILE", 0o644)
				output.Reset()
				called = false
				err = runMigrationProcess(t.Context(), fixture.Input(t, nil), &output, func(context.Context, config.Configuration) error { called = true; return nil })
				if !errors.Is(err, config.ErrSecretResolution) || called {
					t.Fatal("unsafe migration file reached an operation")
				}
				fixture.CheckDiagnostics(t, output.String(), err)
			}
		})
	}
}

func TestDeploymentMigrationCommandRejectsBeforeDatabase(t *testing.T) {
	for _, mode := range []string{"env", "files"} {
		t.Run(mode, func(t *testing.T) {
			fixture := deploymentcheck.Load(t, "compose", "migrate", mode)
			// An owned HTTP endpoint cannot execute PostgreSQL work even if
			// preflight regresses. Count connections before any protocol parsing.
			var connections atomic.Int32
			guard := httptest.NewUnstartedServer(http.NotFoundHandler())
			guard.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			guard.Start()
			defer guard.Close()
			dsn := "postgres://fixture:PRIVATE_PASSWORD@" + guard.Listener.Addr().String() + "/fixture?sslmode=disable&connect_timeout=1"
			overrides := map[string]string{"EVYDENCE_PRIVATE_UNKNOWN": "PRIVATE_VALUE"}
			if mode == "files" {
				fixture.SetFileContents(t, "EVYDENCE_DATABASE_URL_FILE", dsn)
			} else {
				overrides["EVYDENCE_DATABASE_URL"] = dsn
			}
			fixture.Install(t, overrides)
			err := run()
			if !errors.Is(err, config.ErrUnknownOption) || connections.Load() != 0 {
				t.Fatal("actual migration command reached its database before rejecting configuration")
			}
			fixture.CheckDiagnostics(t, "", err)
		})
	}
}
