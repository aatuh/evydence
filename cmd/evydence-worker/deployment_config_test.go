//go:build deployment

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/deploymentcheck"
)

func TestDeploymentWorkerStartup(t *testing.T) {
	for _, source := range deploymentcheck.ServerSources {
		t.Run(source.Name+"-"+source.Mode, func(t *testing.T) {
			fixture := deploymentcheck.Load(t, source.Name, "worker", source.Mode)
			for _, role := range []config.Role{config.Worker, config.WorkerReplay, config.WorkerReconcile} {
				t.Run(fmt.Sprint(role), func(t *testing.T) {
					environment := fixture.Input(t, nil)
					t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_CHANGED_AFTER_CAPTURE")
					t.Setenv("EVYDENCE_RUNTIME_PROFILE", "PRIVATE_CHANGED_AFTER_CAPTURE")
					t.Setenv("PGSERVICE", "")
					var output bytes.Buffer
					called := false
					err := runWorkerRoleProcess(t.Context(), environment, role, &output, func(ctx context.Context, settings config.Configuration) error {
						called = true
						runtime, err := prepareWorkerRuntime(ctx, settings)
						if err != nil || !settings.Production() || settings.Role() != role || settings.Runtime().PostgresLoadMode != "relational_only" || !runtime.DatabaseConfiguration.Matches(fixture.Expected["EVYDENCE_DATABASE_URL"]) || settings.Storage().S3AccessKeyID.Reveal() != fixture.Expected["EVYDENCE_S3_ACCESS_KEY_ID"] || settings.Storage().S3SecretAccessKey.Reveal() != fixture.Expected["EVYDENCE_S3_SECRET_ACCESS_KEY"] || settings.API().KeyPepper.IsSet() {
							t.Fatal("rendered worker settings were not preserved through startup")
						}
						return nil
					})
					if err != nil || !called {
						t.Fatal("rendered worker did not reach validated startup")
					}
					fixture.CheckDiagnostics(t, output.String(), err)
					conflictOption, conflictValue := "EVYDENCE_DATABASE_URL_FILE", "/PRIVATE_ABSENT/file"
					if source.Mode == "files" {
						conflictOption, conflictValue = "EVYDENCE_DATABASE_URL", fixture.Expected["EVYDENCE_DATABASE_URL"]
					}
					for _, invalid := range []struct {
						option, value string
						want          error
					}{
						{"EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS", "0", config.ErrInvalidValue},
						{"EVYDENCE_PRIVATE_UNKNOWN", "PRIVATE_VALUE", config.ErrUnknownOption},
						{"EVYDENCE_RUNTIME_PROFILE", "local_memory", config.ErrInvalidValue},
						{conflictOption, conflictValue, config.ErrConflictingSecretSources},
					} {
						output.Reset()
						called = false
						err := runWorkerRoleProcess(t.Context(), fixture.Input(t, map[string]string{invalid.option: invalid.value}), role, &output, func(context.Context, config.Configuration) error { called = true; return nil })
						if !errors.Is(err, invalid.want) || called {
							t.Fatal("invalid rendered worker configuration reached startup")
						}
						fixture.CheckDiagnostics(t, output.String(), err)
					}
					if source.Mode == "files" {
						t.Run("malformed-file", func(t *testing.T) {
							fixture.SetFileContents(t, "EVYDENCE_DATABASE_URL_FILE", "PRIVATE_INVALID_DSN")
							output.Reset()
							called = false
							err := runWorkerRoleProcess(t.Context(), fixture.Input(t, nil), role, &output, func(context.Context, config.Configuration) error { called = true; return nil })
							if !errors.Is(err, config.ErrSecretResolution) || called {
								t.Fatal("malformed loaded DSN reached worker startup")
							}
							fixture.CheckDiagnostics(t, output.String(), err)
						})
						t.Run("public-file", func(t *testing.T) {
							fixture.SetFileMode(t, "EVYDENCE_DATABASE_URL_FILE", 0o644)
							output.Reset()
							called = false
							err := runWorkerRoleProcess(t.Context(), fixture.Input(t, nil), role, &output, func(context.Context, config.Configuration) error { called = true; return nil })
							if !errors.Is(err, config.ErrSecretResolution) || called {
								t.Fatal("unsafe rendered file reached worker startup")
							}
							fixture.CheckDiagnostics(t, output.String(), err)
						})
					}
				})
			}
		})
	}
}

func TestDeploymentWorkerProbeCommand(t *testing.T) {
	for _, source := range deploymentcheck.ServerSources {
		t.Run(source.Name+"-"+source.Mode, func(t *testing.T) {
			fixture := deploymentcheck.Load(t, source.Name, "worker", source.Mode)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				if request.URL.Path != "/v1/ready" {
					t.Error("actual worker probe changed its readiness route")
				}
				_, _ = w.Write([]byte(`{"data":{"status":"ok"},"meta":{"process":"worker"}}`))
			}))
			defer server.Close()
			fixture.Install(t, map[string]string{
				"EVYDENCE_WORKER_HEALTH_ADDR": server.Listener.Addr().String(),
				"EVYDENCE_DATABASE_URL":       "PRIVATE_UNUSED_DSN", "EVYDENCE_DATABASE_URL_FILE": "/PRIVATE_UNUSED_FILE",
				"EVYDENCE_RUNTIME_PROFILE": "local_memory", "EVYDENCE_WORKER_BATCH_SIZE": "0",
				"EVYDENCE_WORKER_METRICS_TOKEN_FILE": "/PRIVATE_UNUSED_METRICS",
			})
			err := runWorkerWithContext(t.Context(), []string{"healthcheck"})
			if err != nil || calls.Load() != 1 {
				t.Fatal("actual worker probe required an unused deployment dependency")
			}
			fixture.CheckDiagnostics(t, "", err)
			calls.Store(0)
			t.Setenv("EVYDENCE_LOG_FORMAT", "PRIVATE_INVALID")
			err = runWorkerWithContext(t.Context(), []string{"healthcheck"})
			if !errors.Is(err, config.ErrInvalidValue) || calls.Load() != 0 {
				t.Fatal("invalid actual probe configuration reached its listener")
			}
			fixture.CheckDiagnostics(t, "", err)
		})
	}
}
