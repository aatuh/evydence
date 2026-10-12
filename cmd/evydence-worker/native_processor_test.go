package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// Native worker composition must not require or expose LoadState/SaveState.
type nativeProcessorStoreFake struct {
	app.ObjectPayloadLifecycleStore
	jobDependencyInspector
	state         app.PersistedState
	loads, writes int
}

func (f *nativeProcessorStoreFake) LoadWorkerJobState(context.Context, postgres.ClaimedJob) (app.PersistedState, bool, error) {
	f.loads++
	return f.state, true, nil
}
func (f *nativeProcessorStoreFake) ApplyClaimedReleaseLedgerMutation(context.Context, string, string, app.ReleaseLedgerMutation) error {
	f.writes++
	return nil
}

type nativeProcessorObjectsFake struct {
	app.PayloadObjectStore
	app.BoundedObjectReader
}
type nativeUnboundedObjectsFake struct{ app.ObjectStore }

type nativeBoundedReadFake struct {
	gets, bounded int
	limit         int64
	object        app.Object
	err           error
}

func (f *nativeBoundedReadFake) Get(context.Context, string) (app.Object, error) {
	f.gets++
	return app.Object{}, errors.New("unbounded read forbidden")
}
func (f *nativeBoundedReadFake) GetBounded(_ context.Context, _ string, limit int64) (app.Object, error) {
	f.bounded++
	f.limit = limit
	return f.object, f.err
}

func TestWorkerObjectReplayUsesBoundedReaderBeforeParsing(t *testing.T) {
	job := postgres.ClaimedJob{Kind: "parse_sbom", TenantID: "tenant", Payload: map[string]any{"payload_ref": "object://tenants/tenant/raw/test"}}
	f := &nativeBoundedReadFake{object: app.Object{Key: "tenants/tenant/raw/test", TenantID: "tenant", Bytes: []byte("source")}}
	v, ok, err := verifyJobObject(t.Context(), nil, f, job)
	if err != nil || !ok || string(v.Bytes) != "source" || f.gets != 0 || f.bounded != 1 || f.limit != int64(intEnv("EVYDENCE_WORKER_MAX_PAYLOAD_BYTES", defaultMaxWorkerPayloadBytes)) {
		t.Fatal("worker used unbounded object replay", err, f)
	}
	f.err = app.ErrConflict
	if _, ok, err := verifyJobObject(t.Context(), nil, f, job); err == nil || ok || f.gets != 0 || f.bounded != 2 || classifyWorkerFailure(err).Class != postgres.JobFailurePoisoned {
		t.Fatal("bounded rejection did not remain terminal and bounded", err, f)
	}
	f.err = context.Canceled
	if _, ok, err := verifyJobObject(t.Context(), nil, f, job); ok || !errors.Is(err, context.Canceled) || classifyWorkerFailure(err).Code != "worker_interrupted" || f.gets != 0 {
		t.Fatal("bounded cancellation lost its identity", err, f)
	}
}

func TestNativeWorkerDoesNotRequireAggregatePorts(t *testing.T) {
	store := &nativeProcessorStoreFake{state: app.PersistedState{SBOMs: map[string]domain.SBOM{"sbom": {ID: "sbom", TenantID: "tenant", SpecVersion: "1.6"}}}}
	p, err := newNativeJobProcessor(store, &nativeProcessorObjectsFake{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(t.Context(), postgres.ClaimedJob{ID: "job", TenantID: "tenant", Kind: "parse_sbom", SubjectID: "sbom", LeaseToken: "lease"}); err != nil {
		t.Fatal(err)
	}
	if store.loads != 1 || store.writes != 0 {
		t.Fatal("parsed subject reread or rewritten", store)
	}
	if err := p.Process(t.Context(), postgres.ClaimedJob{Kind: "unknown"}); err == nil || classifyWorkerFailure(err).Class != postgres.JobFailurePoisoned {
		t.Fatal("unknown job accepted or misclassified", err)
	}
	if store.loads != 1 || store.writes != 0 {
		t.Fatal("unknown job reached state", store)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := p.Process(ctx, postgres.ClaimedJob{Kind: "parse_sbom"}); !errors.Is(err, context.Canceled) || store.loads != 1 {
		t.Fatal("cancelled job reached state", err)
	}
}
func TestNativeWorkerRejectsIncompleteAndTypedNilPorts(t *testing.T) {
	for _, store := range []nativeJobStateStore{nil, (*nativeProcessorStoreFake)(nil)} {
		if p, err := newNativeJobProcessor(store, &nativeProcessorObjectsFake{}); p != nil || err == nil {
			t.Fatal("missing native state accepted")
		}
	}
	for _, objects := range []app.ObjectStore{nil, (*nativeProcessorObjectsFake)(nil), &nativeUnboundedObjectsFake{}} {
		if p, err := newNativeJobProcessor(&nativeProcessorStoreFake{}, objects); p != nil || err == nil {
			t.Fatal("missing native object capabilities accepted")
		}
	}
}
func TestUnknownWorkerJobsAndIncompleteFocusedStoresNeverFallBack(t *testing.T) {
	legacy := &fakeStateStore{ok: true}
	if err := processJob(t.Context(), legacy, postgres.ClaimedJob{Kind: "unknown"}); err == nil || legacy.loadCalls != 0 {
		t.Fatal("unknown job loaded an aggregate", err, legacy.loadCalls)
	}
	focused := &fakeFocusedReadOnlyStateStore{}
	if _, _, err := loadOutboxJobState(t.Context(), focused, postgres.ClaimedJob{Kind: "parse_sbom"}); err == nil || focused.loadCalls != 0 || focused.focusCalls != 0 {
		t.Fatal("incomplete native parser ports reached data", err, focused)
	}
	if _, _, err := loadOutboxJobState(t.Context(), focused, postgres.ClaimedJob{Kind: "unknown"}); err == nil || focused.loadCalls != 0 || focused.focusCalls != 0 {
		t.Fatal("unknown focused job reached data", err, focused)
	}
}
func TestWorkerPollWaitStopsImmediatelyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitWorkerPoll(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal("worker idle wait lost cancellation", err)
	}
}
