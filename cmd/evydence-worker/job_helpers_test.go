package main

import (
	"context"
	"os"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/wiring"
)

// Legacy fixture helpers select an explicit replay budget. Production composes
// nativeJobProcessor once and never consults an environment reader per job.
func processJob(ctx context.Context, state any, job postgres.ClaimedJob) error {
	return processJobInternal(ctx, state, nil, job, false, defaultMaxWorkerPayloadBytes)
}

func processJobWithObjects(ctx context.Context, state any, objects jobObjectGetter, job postgres.ClaimedJob) error {
	return processJobInternal(ctx, state, objects, job, true, defaultMaxWorkerPayloadBytes)
}

// Fixture-only capture supplies typed storage configuration to the same adapter
// projection used by production. No legacy environment parser remains in wiring.
func openObjectStore(ctx context.Context) (app.ObjectStore, string, error) {
	entries := []string{"EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_DATABASE_URL=host=fixture"}
	for _, name := range []string{"EVYDENCE_OBJECT_STORE", "EVYDENCE_OBJECT_DIR", "EVYDENCE_S3_ENDPOINT", "EVYDENCE_S3_ACCESS_KEY_ID", "EVYDENCE_S3_SECRET_ACCESS_KEY", "EVYDENCE_S3_BUCKET", "EVYDENCE_S3_REGION", "EVYDENCE_S3_USE_SSL"} {
		if value, present := os.LookupEnv(name); present {
			entries = append(entries, name+"="+value)
		}
	}
	environment, err := config.Capture(entries)
	if err != nil {
		return nil, "", err
	}
	settings, err := config.Parse(environment, config.Worker)
	if err != nil {
		return nil, "", err
	}
	return wiring.OpenObjectStore(ctx, wiring.ObjectStoreConfigFromSettings(settings.Storage()))
}
