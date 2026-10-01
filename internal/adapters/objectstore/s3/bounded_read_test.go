package s3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/aatuh/evydence/internal/app"
)

func TestBoundedS3ReadPreservesIntegrityAndRejectsOversizedObjects(t *testing.T) {
	store, server := newFakeS3StoreWithServer(t)
	body := []byte("trusted envelope")
	digest := boundedTestDigest(body)
	key := "tenants/tenant/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:")
	object := app.Object{Key: key, TenantID: "tenant", MediaType: "application/json", Digest: digest, Bytes: body, CreatedAt: time.Now().UTC()}
	if err := store.Put(t.Context(), object); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetBounded(t.Context(), key, int64(len(body))); err != nil || string(got.Bytes) != string(body) || got.TenantID != "tenant" || got.Digest != digest {
		t.Fatal(got, err)
	}
	if got, err := store.GetBounded(t.Context(), key, int64(len(body)-1)); !errors.Is(err, app.ErrConflict) || len(got.Bytes) != 0 {
		t.Fatal("oversized read returned data", err)
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
		if _, err := store.GetBounded(t.Context(), key, 1024); !errors.Is(err, app.ErrValidation) {
			t.Fatal("unsafe key", key, err)
		}
	}
	server.mu.Lock()
	changed := server.objects[key]
	changed.tenantID = "foreign"
	server.objects[key] = changed
	server.mu.Unlock()
	if _, err := store.GetBounded(t.Context(), key, 1024); !errors.Is(err, app.ErrValidation) {
		t.Fatal("foreign provider metadata trusted", err)
	}
	server.mu.Lock()
	changed.tenantID = "tenant"
	changed.body = []byte("tampered envelope")
	server.objects[key] = changed
	server.mu.Unlock()
	if _, err := store.GetBounded(t.Context(), key, 1024); !errors.Is(err, app.ErrValidation) {
		t.Fatal("tampered payload trusted", err)
	}
}

// A fake transport lets HEAD and GET disagree without relying on a real
// provider or HTTP Content-Length corruption. Streaming limits must still win.
type growingObjectTransport struct {
	http.RoundTripper
	read   *atomic.Int64
	closed chan struct{}
}

func (t growingObjectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.RoundTripper.RoundTrip(r)
	if err == nil && r.Method == http.MethodHead && response.StatusCode == 200 {
		response.Header.Set("Content-Length", "1")
		response.ContentLength = 1
	}
	if err == nil && r.Method == http.MethodGet && response.StatusCode == http.StatusOK {
		response.Body = &countedObjectBody{ReadCloser: response.Body, read: t.read, closed: t.closed}
	}
	return response, err
}

type countedObjectBody struct {
	io.ReadCloser
	read   *atomic.Int64
	closed chan struct{}
}

func (b *countedObjectBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read.Add(int64(n))
	return n, err
}

func (b *countedObjectBody) Close() error {
	err := b.ReadCloser.Close()
	close(b.closed)
	return err
}

func TestBoundedS3ReadRejectsGrowthBetweenStatAndBodyRead(t *testing.T) {
	server := &fakeS3Server{objects: map[string]fakeS3Object{}}
	httpServer := httptest.NewServer(http.HandlerFunc(server.handle))
	t.Cleanup(httpServer.Close)
	var read atomic.Int64
	closed := make(chan struct{})
	client, err := minio.New(strings.TrimPrefix(httpServer.URL, "http://"), &minio.Options{Creds: credentials.NewStaticV4("access", "secret", ""), Region: "us-east-1", Transport: growingObjectTransport{RoundTripper: http.DefaultTransport, read: &read, closed: closed}})
	if err != nil {
		t.Fatal(err)
	}
	store := &Store{client: client, bucket: "evidence"}
	body := []byte("trusted envelope")
	digest := boundedTestDigest(body)
	key := "tenants/tenant/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:")
	if err := store.Put(t.Context(), app.Object{Key: key, TenantID: "tenant", Digest: digest, MediaType: "application/json", Bytes: body}); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetBounded(t.Context(), key, 4); !errors.Is(err, app.ErrConflict) || len(got.Bytes) != 0 {
		t.Fatal("body exceeded requested limit", err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("bounded read did not close provider response")
	}
	if got := read.Load(); got != 5 {
		t.Fatalf("read %d payload bytes, want only the limit and one overflow byte", got)
	}
}

func boundedTestDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
