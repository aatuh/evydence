package main

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

type configuredLimitObjects struct {
	app.PayloadObjectStore
	reader *nativeBoundedReadFake
}

func (f *configuredLimitObjects) Get(ctx context.Context, key string) (app.Object, error) {
	return f.reader.Get(ctx, key)
}
func (f *configuredLimitObjects) GetBounded(ctx context.Context, key string, limit int64) (app.Object, error) {
	return f.reader.GetBounded(ctx, key, limit)
}

func TestConfiguredWorkerPayloadLimitDoesNotRereadEnvironment(t *testing.T) {
	store := &nativeProcessorStoreFake{}
	reader := &nativeBoundedReadFake{err: app.ErrConflict}
	processor, err := newNativeJobProcessor(store, &configuredLimitObjects{reader: reader}, 17)
	if err != nil {
		t.Fatal(err)
	}
	job := postgres.ClaimedJob{ID: "job", Kind: "parse_sbom", TenantID: "tenant", SubjectID: "sbom", LeaseToken: "lease", Payload: map[string]any{"payload_ref": "object://tenants/tenant/raw/payload"}}
	for index, raw := range []string{"1", "999999", "PRIVATE_INVALID"} {
		t.Setenv("EVYDENCE_WORKER_MAX_PAYLOAD_BYTES", raw)
		err := processor.Process(t.Context(), job)
		if !errors.Is(err, errWorkerBoundedPayloadRejected) || reader.limit != 17 || reader.bounded != index+1 || reader.gets != 0 || store.loads != 0 || store.writes != 0 {
			t.Fatal("job observed mutable input or reached state after a bounded rejection", err)
		}
	}
}

func TestConfiguredWorkerPayloadLimitRejectsInvalidBudgets(t *testing.T) {
	for _, limit := range []int64{-1, 0, math.MaxInt64} {
		store := &nativeProcessorStoreFake{}
		reader := &nativeBoundedReadFake{}
		processor, err := newNativeJobProcessor(store, &configuredLimitObjects{reader: reader}, limit)
		if processor != nil || err == nil || reader.bounded != 0 || reader.gets != 0 || store.loads != 0 || store.writes != 0 {
			t.Fatal("invalid byte budget reached a worker port")
		}
	}
}
