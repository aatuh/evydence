package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestStorePutGetTenantPrefixedObject(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"ok":true}`)
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	object := app.Object{
		Key:       "tenants/ten_1/payloads/sbom/" + strings.TrimPrefix(digest, "sha256:"),
		TenantID:  "ten_1",
		MediaType: "application/json",
		Digest:    digest,
		Bytes:     body,
		CreatedAt: time.Now().UTC(),
	}

	if err := store.Put(context.Background(), object); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), object.Key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Bytes) != string(body) || got.TenantID != "ten_1" || got.Digest != digest {
		t.Fatalf("unexpected object: %#v", got)
	}
	if _, err := os.Stat(filepath.Join(store.root, object.Key+".json")); err != nil {
		t.Fatalf("metadata missing: %v", err)
	}
}

func TestStoreRejectsUnsafeObjectKeys(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("payload"))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	object := app.Object{
		Key:      "../escape",
		TenantID: "ten_1",
		Digest:   digest,
		Bytes:    []byte("payload"),
	}
	if err := store.Put(context.Background(), object); err == nil {
		t.Fatal("expected traversal key to be rejected")
	}
	object.Key = "tenants/ten_other/payloads/sbom/" + strings.TrimPrefix(digest, "sha256:")
	if err := store.Put(context.Background(), object); err == nil {
		t.Fatal("expected non-tenant-prefixed key to be rejected")
	}
}

func TestStoreStagesFinalizesAndVerifiesPayloadIdempotently(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("staged object payload")
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	payload := app.ObjectPayload{
		TenantID:   "ten_1",
		Digest:     digest,
		MediaType:  "application/octet-stream",
		StagingKey: "tenants/ten_1/staging/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		FinalKey:   "tenants/ten_1/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		Status:     app.ObjectPayloadStaged,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	payload, err = store.StagePayload(context.Background(), payload, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("stage payload: %v", err)
	}
	if payload.Size != int64(len(body)) || payload.Status != app.ObjectPayloadStaged {
		t.Fatalf("staged payload = %#v", payload)
	}
	if _, err := store.Get(context.Background(), payload.FinalKey); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("final object before finalization err=%v, want not found", err)
	}
	finalized, err := store.FinalizePayload(context.Background(), payload)
	if err != nil {
		t.Fatalf("finalize payload: %v", err)
	}
	if finalized.Key != payload.FinalKey || finalized.Digest != digest || string(finalized.Bytes) != string(body) {
		t.Fatalf("finalized object = %#v", finalized)
	}
	if _, err := store.Get(context.Background(), payload.StagingKey); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("staging object after finalization err=%v, want not found", err)
	}
	if _, err := store.FinalizePayload(context.Background(), payload); err != nil {
		t.Fatalf("repeat finalization: %v", err)
	}
}

func TestStoreRejectsStagedPayloadDigestMismatch(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	now := time.Now().UTC()
	payload := app.ObjectPayload{
		TenantID:   "ten_1",
		Digest:     digest,
		StagingKey: "tenants/ten_1/staging/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		FinalKey:   "tenants/ten_1/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		Status:     app.ObjectPayloadStaged,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if _, err := store.StagePayload(context.Background(), payload, bytes.NewReader([]byte("wrong bytes"))); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("digest mismatch error=%v, want validation", err)
	}
	if _, err := store.Get(context.Background(), payload.StagingKey); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("mismatched staging object err=%v, want not found", err)
	}
}

func TestPayloadStorageHelpersRejectInvalidAndInterruptedWork(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", "../escape", "/absolute", "tenants/ten_1/../ten_2/raw"} {
		if _, err := safeObjectKey(key); err == nil {
			t.Fatalf("unsafe key %q was accepted", key)
		}
	}
	if err := store.remove("tenants/ten_1/staging/missing"); err != nil {
		t.Fatalf("removing a missing staged key should be idempotent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := copyWithContext(ctx, &bytes.Buffer{}, bytes.NewReader([]byte("body"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled copy error=%v", err)
	}
	readErr := errors.New("read failure")
	if _, err := copyWithContext(context.Background(), &bytes.Buffer{}, failingReader{err: readErr}); !errors.Is(err, readErr) {
		t.Fatalf("reader failure error=%v", err)
	}
	digestForMissing := "sha256:" + strings.Repeat("a", 64)
	stagingKey, finalKey, err := app.CanonicalObjectPayloadKeys("ten_1", digestForMissing)
	if err != nil {
		t.Fatal(err)
	}
	payload := app.ObjectPayload{TenantID: "ten_1", Digest: digestForMissing, Size: 1, MediaType: "application/octet-stream", StagingKey: stagingKey, FinalKey: finalKey, Status: app.ObjectPayloadStaged, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if _, err := store.StagePayload(context.Background(), payload, nil); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil staged reader error=%v", err)
	}
	if _, err := store.StagePayload(ctx, payload, bytes.NewReader([]byte("x"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled staging error=%v", err)
	}
	if _, err := store.FinalizePayload(context.Background(), payload); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing staged finalization error=%v, want not found", err)
	}
	if err := verifyPayloadObject(payload, app.Object{Key: payload.StagingKey, TenantID: "ten_other", Digest: payload.Digest, Bytes: []byte("x")}, payload.StagingKey); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("cross-tenant object validation error=%v", err)
	}
}

func TestStoreReadinessChecksConfiguredRootAccess(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CheckReadiness(t.Context()); err != nil {
		t.Fatalf("object store readiness: %v", err)
	}
	if _, err := os.ReadDir(store.root); err != nil {
		t.Fatalf("read readiness root: %v", err)
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("readiness marker was not removed: %#v", entries)
	}
}

func TestStoreListsTenantObjectInventoryWithoutMetadataSidecars(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range []app.Object{
		inventoryObject("ten_1", "tenants/ten_1/payloads/sha256/001", []byte("one")),
		inventoryObject("ten_1", "tenants/ten_1/staging/sha256/002", []byte("two")),
		inventoryObject("ten_2", "tenants/ten_2/payloads/sha256/003", []byte("three")),
	} {
		if err := store.Put(t.Context(), object); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.ListObjectInventory(t.Context(), "ten_1", 0, 1)
	if err != nil || len(page.Objects) != 1 || page.NextCursor != 1 {
		t.Fatalf("first inventory page=%#v err=%v", page, err)
	}
	if page.Objects[0].TenantID != "ten_1" || strings.HasSuffix(page.Objects[0].Key, ".json") {
		t.Fatalf("unsafe inventory item=%#v", page.Objects[0])
	}
	page, err = store.ListObjectInventory(t.Context(), "ten_1", page.NextCursor, 1)
	if err != nil || len(page.Objects) != 1 || page.NextCursor != 0 {
		t.Fatalf("second inventory page=%#v err=%v", page, err)
	}
	if _, err := store.ListObjectInventory(t.Context(), "../ten_2", 0, 1); err == nil {
		t.Fatal("unsafe inventory tenant was accepted")
	}
}

func inventoryObject(tenantID, key string, body []byte) app.Object {
	sum := sha256.Sum256(body)
	return app.Object{Key: key, TenantID: tenantID, Digest: "sha256:" + hex.EncodeToString(sum[:]), Bytes: body, CreatedAt: time.Now().UTC()}
}

func TestStoreRootedOperationsRejectSymlinkEscape(t *testing.T) {
	storeRoot := t.TempDir()
	outside := t.TempDir()
	store, err := New(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(storeRoot, "tenants")); err != nil {
		t.Fatal(err)
	}
	body := []byte("outside payload")
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	key := "tenants/ten_1/payloads/sbom/" + strings.TrimPrefix(digest, "sha256:")
	object := app.Object{Key: key, TenantID: "ten_1", MediaType: "application/json", Digest: digest, Bytes: body, CreatedAt: time.Now().UTC()}

	if err := store.Put(t.Context(), object); err == nil {
		t.Fatal("write through escaping symlink succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "ten_1", "payloads", "sbom", strings.TrimPrefix(digest, "sha256:"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("escaping write created outside object: %v", err)
	}

	outsideObject := filepath.Join(outside, "ten_1", "payloads", "sbom", strings.TrimPrefix(digest, "sha256:"))
	if err := os.MkdirAll(filepath.Dir(outsideObject), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideObject, body, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := metadata{Key: key, TenantID: "ten_1", MediaType: "application/json", Digest: digest, Size: int64(len(body)), CreatedAt: time.Now().UTC()}
	metaBody, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideObject+".json", metaBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(t.Context(), key); err == nil {
		t.Fatalf("read through escaping symlink succeeded: %#v", got)
	}
}

func TestStoreGetRejectsTamperedPayloadAndMetadata(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("trusted payload")
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	key := "tenants/ten_tamper/payloads/sbom/" + strings.TrimPrefix(digest, "sha256:")
	object := app.Object{Key: key, TenantID: "ten_tamper", MediaType: "application/json", Digest: digest, Bytes: body, CreatedAt: time.Now().UTC()}
	if err := store.Put(t.Context(), object); err != nil {
		t.Fatal(err)
	}

	objectPath := filepath.Join(store.root, filepath.FromSlash(key))
	if err := os.WriteFile(objectPath, []byte("tampered payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("tampered body err=%v, want validation", err)
	}

	if err := store.Put(t.Context(), object); err != nil {
		t.Fatal(err)
	}
	metaBody, err := os.ReadFile(objectPath + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var meta metadata
	if err := json.Unmarshal(metaBody, &meta); err != nil {
		t.Fatal(err)
	}
	meta.TenantID = "ten_other"
	metaBody, err = json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath+".json", metaBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("tampered metadata err=%v, want validation", err)
	}
}
