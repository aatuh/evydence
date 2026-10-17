package main

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
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

// Object-store construction fixtures retain the legacy wiring tests while
// production commands supply their validated typed storage settings directly.
func openObjectStore(ctx context.Context) (app.ObjectStore, string, error) {
	return wiring.OpenObjectStore(ctx, wiring.ObjectStoreConfigFromEnv())
}
