package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/wiring"
)

func TestWorkerOperatorProcessUsesCapturedRuntimeSettings(t *testing.T) {
	for _, role := range []config.Role{config.WorkerReplay, config.WorkerReconcile} {
		e := workerCapturedEnvironment(t, "EVYDENCE_DATABASE_URL=host=PRIVATE_CAPTURED", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_MISSING/token", "EVYDENCE_WORKER_HEALTH_ADDR=PRIVATE_INVALID", "EVYDENCE_WORKER_BATCH_SIZE=0", "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS=3")
		t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_CHANGED")
		t.Setenv("EVYDENCE_RUNTIME_PROFILE", "local_memory")
		called := false
		var output bytes.Buffer
		err := runWorkerRoleProcess(t.Context(), e, role, &output, func(_ context.Context, settings config.Configuration) error {
			called = true
			runtime := workerRuntimeConfigFromSettings(settings)
			if settings.Role() != role || runtime.DatabaseURL != "host=PRIVATE_CAPTURED" || runtime.Profile != wiring.PostgreSQL || runtime.CleanupTimeout != 3*time.Second || runtime.ObjectStore.Backend != "filesystem" {
				t.Fatal("operator used ambient or incomplete runtime settings")
			}
			return nil
		})
		if !called || err != nil || strings.Contains(output.String(), "PRIVATE") {
			t.Fatal("operator scope failed or leaked captured input", err)
		}
	}
}

func TestParserReplayConfiguredClosesIncompleteRuntimeWithTypedBudget(t *testing.T) {
	settings, err := config.Parse(workerCapturedEnvironment(t, "EVYDENCE_PARSER_REPLAY_TIMEOUT=4s", "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS=3"), config.WorkerReplay)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EVYDENCE_PARSER_REPLAY_TIMEOUT", "PRIVATE_INVALID")
	t.Setenv("EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS", "PRIVATE_INVALID")
	want := errors.New("PRIVATE_CLEANUP_FAILURE")
	previous := openParserReplayRuntime
	t.Cleanup(func() { openParserReplayRuntime = previous })
	closed := 0
	openParserReplayRuntime = func(ctx context.Context, runtime wiring.RuntimeConfig) (parserReplayRuntime, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 4*time.Second || runtime.CleanupTimeout != 3*time.Second {
			t.Fatal("operator ignored typed operation or cleanup budget")
		}
		return parserReplayRuntime{close: func(closeCtx context.Context, budget time.Duration) error {
			closed++
			if closeCtx != ctx || budget != 3*time.Second {
				t.Fatal("replay cleanup lost its context or configured budget")
			}
			return want
		}}, nil
	}
	err = runParserReplayConfigured(t.Context(), settings, parserReplayArgs{TenantID: "ten_test", EvidenceID: "ev_test", ParserVersion: "v1", ActorID: "operator"})
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "runtime is incomplete") || closed != 1 {
		t.Fatal("incomplete runtime lost failure or ownership cleanup", err)
	}
}

type replayBudgetObjects struct {
	app.ObjectStore
	bounded, unbounded int
	limit              int64
	object             app.Object
	err                error
}

func (objects *replayBudgetObjects) Get(context.Context, string) (app.Object, error) {
	objects.unbounded++
	return app.Object{}, app.ErrConflict
}
func (objects *replayBudgetObjects) GetBounded(_ context.Context, _ string, intLimit int64) (app.Object, error) {
	objects.bounded++
	objects.limit = intLimit
	return objects.object, objects.err
}

func TestParserReplayUsesBoundedDomainReadAndClosesAfterRejection(t *testing.T) {
	settings, err := config.Parse(workerCapturedEnvironment(t), config.WorkerReplay)
	if err != nil {
		t.Fatal(err)
	}
	store := &replayStoreStub{state: app.PersistedState{Evidence: map[string]domain.EvidenceItem{"source": {ID: "source", TenantID: "tenant", PayloadRef: "object://tenants/tenant/raw/source"}}}}
	objects := &replayBudgetObjects{err: app.ErrConflict}
	previous := openParserReplayRuntime
	t.Cleanup(func() { openParserReplayRuntime = previous })
	closed := 0
	openParserReplayRuntime = func(context.Context, wiring.RuntimeConfig) (parserReplayRuntime, error) {
		return parserReplayRuntime{store: store, objects: objects, close: func(context.Context, time.Duration) error { closed++; return nil }}, nil
	}
	err = runParserReplayConfigured(t.Context(), settings, parserReplayArgs{TenantID: "tenant", EvidenceID: "source", ParserVersion: app.ParserVersionCycloneDXJSON, ActorID: "operator"})
	if err == nil || objects.unbounded != 0 || objects.bounded != 1 || objects.limit != app.EvidenceDocumentLimit || store.applyCalls != 0 || closed != 1 {
		t.Fatal("operator bypassed its domain byte bound or lost runtime cleanup")
	}
}

type unboundedReplayObjects struct {
	app.ObjectStore
	reads int
}

func (objects *unboundedReplayObjects) Get(context.Context, string) (app.Object, error) {
	objects.reads++
	return app.Object{}, app.ErrConflict
}

func TestParserReplayRejectsUnboundedAndOversizedAdapterResults(t *testing.T) {
	settings, err := config.Parse(workerCapturedEnvironment(t), config.WorkerReplay)
	if err != nil {
		t.Fatal(err)
	}
	document := `{"openapi":"3.0.3","info":{"title":"fixture","version":"1"},"paths":{}}`
	raw := make([]byte, int(app.EvidenceDocumentLimit)+1+len(document))
	for index := range raw[:int(app.EvidenceDocumentLimit)+1] {
		raw[index] = ' '
	}
	copy(raw[int(app.EvidenceDocumentLimit)+1:], document)
	key := "tenants/tenant/raw/source"
	digest := digestBytes(raw)
	oversized := &replayBudgetObjects{object: app.Object{Key: key, TenantID: "tenant", Digest: digest, Bytes: raw}}
	unbounded := &unboundedReplayObjects{}
	previous := openParserReplayRuntime
	t.Cleanup(func() { openParserReplayRuntime = previous })
	for _, tc := range []struct {
		name    string
		objects app.ObjectStore
	}{{"unbounded", unbounded}, {"oversized", oversized}} {
		t.Run(tc.name, func(t *testing.T) {
			store := &replayStoreStub{state: app.PersistedState{Evidence: map[string]domain.EvidenceItem{"source": {ID: "source", TenantID: "tenant", Type: "openapi_contract", PayloadRef: "object://" + key, PayloadHash: digest, CreatedAt: time.Now().UTC()}}}}
			closed := 0
			openParserReplayRuntime = func(context.Context, wiring.RuntimeConfig) (parserReplayRuntime, error) {
				return parserReplayRuntime{store: store, objects: tc.objects, close: func(context.Context, time.Duration) error { closed++; return nil }}, nil
			}
			err := runParserReplayConfigured(t.Context(), settings, parserReplayArgs{TenantID: "tenant", EvidenceID: "source", ParserVersion: app.ParserVersionOpenAPIJSON, ActorID: "operator"})
			if err == nil || store.applyCalls != 0 || closed != 1 || unbounded.reads != 0 || oversized.unbounded != 0 {
				t.Fatal("replay accepted an unbounded adapter, persisted oversized data, or lost cleanup")
			}
		})
	}
	if oversized.bounded != 1 || oversized.limit != app.EvidenceDocumentLimit {
		t.Fatal("oversized return bypassed the bounded port")
	}
}
