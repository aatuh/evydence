package main

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/wiring"
)

func TestPrepareWorkerRuntimeOwnsResolvedDatabaseBeforeResources(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	for _, role := range []config.Role{config.Worker, config.WorkerReplay, config.WorkerReconcile} {
		settings, err := config.Parse(workerCapturedEnvironment(t, "EVYDENCE_DATABASE_URL=host=PRIVATE_CAPTURED port=5544 sslmode=disable"), role)
		if err != nil {
			t.Fatal(err)
		}
		runtime, err := prepareWorkerRuntime(t.Context(), settings)
		if err != nil || !runtime.DatabaseConfiguration.IsPrepared() || !runtime.DatabaseConfiguration.Matches(settings.Runtime().DatabaseURL.Reveal()) {
			t.Fatal("worker lost prepared native database settings", err)
		}
	}
}

func TestPrepareWorkerRuntimeRejectsUnresolvedNativeService(t *testing.T) {
	t.Setenv("PGSERVICE", "PRIVATE_MISSING")
	t.Setenv("PGSERVICEFILE", "/PRIVATE_MISSING/file")
	for _, role := range []config.Role{config.Worker, config.WorkerReplay, config.WorkerReconcile} {
		settings, err := config.Parse(workerCapturedEnvironment(t, "PGSERVICE=PRIVATE_MISSING", "PGSERVICEFILE=/PRIVATE_MISSING/file"), role)
		if err != nil {
			t.Fatal("pure configuration incorrectly entered native resolution", err)
		}
		runtime, err := prepareWorkerRuntime(t.Context(), settings)
		if !errors.Is(err, postgres.ErrInvalidConfiguration) || !reflect.DeepEqual(runtime, wiring.RuntimeConfig{}) {
			t.Fatal("native resolution failure exposed partial worker startup settings", err)
		}
	}
}
