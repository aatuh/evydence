package s3

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestNewRejectsIncompleteConfigWithoutNetwork(t *testing.T) {
	_, err := New(context.Background(), Config{Endpoint: "localhost:9000", Bucket: "evydence"})
	if !errors.Is(err, app.ErrValidation) {
		t.Fatalf("err = %v, want validation", err)
	}
}

func TestPutGetRejectUninitializedStoreAndUnsafeKeys(t *testing.T) {
	if err := (*Store)(nil).Put(context.Background(), app.Object{Key: "tenants/ten_1/raw", TenantID: "ten_1"}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil put err = %v, want validation", err)
	}
	if _, err := (*Store)(nil).Get(context.Background(), "tenants/ten_1/raw"); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil get err = %v, want validation", err)
	}

	store := &Store{}
	err := store.Put(context.Background(), app.Object{Key: "tenants/other/raw", TenantID: "ten_1"})
	if !errors.Is(err, app.ErrValidation) {
		t.Fatalf("cross-tenant key err = %v, want validation", err)
	}
	if _, err := store.Get(context.Background(), ""); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("empty key err = %v, want validation", err)
	}
}

func TestMetadataValueUsesFirstNonEmptyKey(t *testing.T) {
	metadata := map[string]string{
		"X-Amz-Meta-Evydence-Tenant-Id": "",
		"evydence-tenant-id":            "ten_1",
		"evydence-digest":               "sha256:abc",
	}
	if got := metadataValue(metadata, "X-Amz-Meta-Evydence-Tenant-Id", "evydence-tenant-id"); got != "ten_1" {
		t.Fatalf("tenant metadata = %q", got)
	}
	if got := metadataValue(metadata, "missing", "evydence-digest"); got != "sha256:abc" {
		t.Fatalf("digest metadata = %q", got)
	}
	if got := metadataValue(metadata, "missing"); got != "" {
		t.Fatalf("missing metadata = %q", got)
	}
}
