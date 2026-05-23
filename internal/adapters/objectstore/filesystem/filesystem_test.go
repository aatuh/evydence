package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

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
