package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type storageTelemetryFixture struct {
	mu     sync.Mutex
	events []telemetry.Event
	active map[telemetry.Operation]int
}

func (o *storageTelemetryFixture) Observe(_ context.Context, event telemetry.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event)
}
func (o *storageTelemetryFixture) Begin(operation telemetry.Operation) func() {
	o.mu.Lock()
	if o.active == nil {
		o.active = map[telemetry.Operation]int{}
	}
	o.active[operation]++
	o.mu.Unlock()
	return func() { o.mu.Lock(); o.active[operation]--; o.mu.Unlock() }
}
func TestStorageTelemetryPreservesResultsIntegrityCancellationAndLabels(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	observer := &storageTelemetryFixture{}
	ctx := telemetry.WithObserver(t.Context(), observer)
	body := []byte("PRIVATE_OBJECT_BYTES")
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	key := "tenants/ten_private/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:")
	object := app.Object{Key: key, TenantID: "ten_private", Digest: digest, Bytes: body, MediaType: "application/octet-stream", CreatedAt: time.Now().UTC()}
	if err := store.Put(ctx, object); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(ctx, key); err != nil || !bytes.Equal(got.Bytes, body) || got.Digest != digest {
		t.Fatal("measurement changed object bytes or metadata", err)
	}
	if got, err := store.GetBounded(ctx, key, 1); !errors.Is(err, app.ErrConflict) || len(got.Bytes) != 0 {
		t.Fatal("bounded integrity rejection changed", err)
	}
	if _, err := store.Get(ctx, "../PRIVATE_PATH"); !errors.Is(err, app.ErrValidation) {
		t.Fatal("unsafe path rejection changed", err)
	}
	if _, err := store.ListObjectInventory(ctx, "ten_private", 0, 10); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.GetBounded(canceled, key, 100); !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation changed", err)
	}
	payloadBody := []byte("PRIVATE_STAGED_BYTES")
	payloadSum := sha256.Sum256(payloadBody)
	payloadDigest := "sha256:" + hex.EncodeToString(payloadSum[:])
	now := time.Now().UTC()
	payload := app.ObjectPayload{TenantID: "ten_private", Digest: payloadDigest, MediaType: "application/octet-stream", Status: app.ObjectPayloadStaged, CreatedAt: now, UpdatedAt: now, StagingKey: "tenants/ten_private/staging/sha256/" + strings.TrimPrefix(payloadDigest, "sha256:"), FinalKey: "tenants/ten_private/payloads/sha256/" + strings.TrimPrefix(payloadDigest, "sha256:")}
	staged, err := store.StagePayload(ctx, payload, bytes.NewReader(payloadBody))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.FinalizePayload(ctx, staged); err != nil || !bytes.Equal(got.Bytes, payloadBody) || got.Key != payload.FinalKey {
		t.Fatal("measured finalization changed immutable payload", err)
	}

	found := map[telemetry.Operation]map[telemetry.Outcome]bool{}
	for _, event := range observer.events {
		if event.Duration < 0 {
			t.Fatal("negative storage duration")
		}
		if found[event.Operation] == nil {
			found[event.Operation] = map[telemetry.Outcome]bool{}
		}
		found[event.Operation][event.Outcome] = true
	}
	for _, op := range []telemetry.Operation{telemetry.OperationObjectWrite, telemetry.OperationObjectRead, telemetry.OperationObjectList, telemetry.OperationObjectStage, telemetry.OperationObjectFinalize, telemetry.OperationObjectDelete} {
		if !found[op][telemetry.OutcomeSucceeded] {
			t.Fatal("storage operation success was not measured", op)
		}
	}
	if !found[telemetry.OperationObjectRead][telemetry.OutcomeFailed] || !found[telemetry.OperationObjectRead][telemetry.OutcomeCanceled] {
		t.Fatal("storage failure or cancellation not measured")
	}
	for op, count := range observer.active {
		if count != 0 {
			t.Fatal("storage activity leaked", op, count)
		}
	}
	if len(observer.active) < 5 {
		t.Fatal("storage activity was not measured")
	}
	encoded, err := json.Marshal(observer.events)
	if err != nil || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "ten_private") {
		t.Fatal("storage telemetry exposed identities, paths or evidence", err)
	}
}
