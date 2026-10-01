package filesystem

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

func TestBoundedObjectReadPreservesIntegrityAndRejectsOversizedFiles(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("trusted envelope")
	digest := digestBytes(body)
	key := "tenants/tenant/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:")
	object := app.Object{Key: key, TenantID: "tenant", MediaType: "application/vnd.dsse.envelope+json", Digest: digest, Bytes: body, CreatedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	if err := store.Put(t.Context(), object); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetBounded(t.Context(), key, int64(len(body))); err != nil || !reflect.DeepEqual(got, object) {
		t.Fatal("exact bound lost object", got, err)
	}
	if got, err := store.GetBounded(t.Context(), key, int64(len(body)-1)); !errors.Is(err, app.ErrConflict) || len(got.Bytes) != 0 {
		t.Fatal("oversized file returned partial bytes", err)
	}
	for _, limit := range []int64{-1, 0, math.MaxInt64} {
		if _, err := store.GetBounded(t.Context(), key, limit); !errors.Is(err, app.ErrValidation) {
			t.Fatal("unsafe bound", limit, err)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.GetBounded(cancelled, key, 1024); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read", err)
	}
	for _, key := range []string{"../outside", "/outside", "tenants/tenant/../outside"} {
		if _, err := store.GetBounded(t.Context(), key, 1024); err == nil {
			t.Fatal("unsafe key accepted", key)
		}
	}
	path := filepath.Join(store.root, filepath.FromSlash(key))
	if err := os.WriteFile(path, []byte("tampered envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetBounded(t.Context(), key, 1024); !errors.Is(err, app.ErrValidation) {
		t.Fatal("tampered payload accepted", err)
	}
	if err := store.Put(t.Context(), object); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name string
		edit func(*metadata)
	}{
		{"foreign tenant", func(m *metadata) { m.TenantID = "foreign" }},
		{"foreign key", func(m *metadata) { m.Key = "tenants/foreign/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:") }},
		{"wrong size", func(m *metadata) { m.Size++ }},
		{"wrong digest", func(m *metadata) { m.Digest = digestBytes([]byte("other")) }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			m := metadata{Key: key, TenantID: object.TenantID, MediaType: object.MediaType, Digest: digest, Size: int64(len(body)), CreatedAt: object.CreatedAt}
			mutate.edit(&m)
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".json", data, 0o600); err != nil {
				t.Fatal(err)
			}
			if got, err := store.GetBounded(t.Context(), key, 1024); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(got, app.Object{}) {
				t.Fatal("invalid metadata returned an object", err)
			}
		})
	}
	if err := os.WriteFile(path+".json", []byte(strings.Repeat(" ", 64*1024)+`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetBounded(t.Context(), key, 1024); !errors.Is(err, app.ErrConflict) || len(got.Bytes) != 0 {
		t.Fatal("oversized metadata accepted", err)
	}
}

func TestBoundedObjectReadRejectsEscapingSymlinkAndNonregularFiles(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("payload")
	digest := digestBytes(body)
	key := "tenants/tenant/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:")
	object := app.Object{Key: key, TenantID: "tenant", MediaType: "application/json", Digest: digest, Bytes: body, CreatedAt: time.Now().UTC()}
	if err := store.Put(t.Context(), object); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.root, filepath.FromSlash(key))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetBounded(t.Context(), key, 1024); err == nil || len(got.Bytes) != 0 {
		t.Fatal("escaping symlink read", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetBounded(t.Context(), key, 1024); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nonregular object accepted", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(t.Context(), object); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + ".json"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".json", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetBounded(t.Context(), key, 1024); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nonregular metadata accepted", err)
	}
}
