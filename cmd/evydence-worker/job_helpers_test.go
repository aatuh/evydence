package main

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/postgres"
)

// Legacy fixture helpers select an explicit replay budget. Production composes
// nativeJobProcessor once and never consults an environment reader per job.
func processJob(ctx context.Context, state any, job postgres.ClaimedJob) error {
	return processJobInternal(ctx, state, nil, job, false, defaultMaxWorkerPayloadBytes)
}

func processJobWithObjects(ctx context.Context, state any, objects jobObjectGetter, job postgres.ClaimedJob) error {
	return processJobInternal(ctx, state, objects, job, true, defaultMaxWorkerPayloadBytes)
}
