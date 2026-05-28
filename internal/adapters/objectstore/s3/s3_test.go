package s3

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"

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

func TestEvaluateObjectRetentionRequiresVersioningLockAndTenantPrefix(t *testing.T) {
	mode := minio.Compliance
	validity := uint(90)
	unit := minio.Days
	result := evaluateObjectRetention(app.ObjectRetentionRequest{
		TenantID:      "ten_1",
		ObjectPrefix:  "tenants/ten_1/raw/",
		Mode:          "compliance",
		RetentionDays: 30,
	}, true, &mode, &validity, &unit, nil, nil, time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC))
	if !result.Enforced {
		t.Fatalf("expected enforced retention: %#v", result)
	}
	if len(result.Checks) != 4 || result.Checks[0].Result != "passed" {
		t.Fatalf("checks = %#v", result.Checks)
	}
	if len(result.Limitations) == 0 {
		t.Fatal("expected limitations")
	}
}

func TestEvaluateObjectRetentionReportsMissingProviderControls(t *testing.T) {
	mode := minio.Governance
	validity := uint(1)
	unit := minio.Days
	result := evaluateObjectRetention(app.ObjectRetentionRequest{
		TenantID:      "ten_1",
		ObjectPrefix:  "tenants/other/raw/",
		Mode:          "compliance",
		RetentionDays: 30,
	}, false, &mode, &validity, &unit, nil, nil, time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC))
	if result.Enforced {
		t.Fatalf("unexpected enforced retention: %#v", result)
	}
	failed := 0
	for _, check := range result.Checks {
		if check.Result == "failed" {
			failed++
		}
	}
	if failed != 4 {
		t.Fatalf("failed checks = %d, checks = %#v", failed, result.Checks)
	}
}

func TestEvaluateObjectRetentionChecksSampleObjectRetention(t *testing.T) {
	mode := minio.Compliance
	validity := uint(90)
	unit := minio.Days
	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	retainUntil := now.Add(45 * 24 * time.Hour)
	result := evaluateObjectRetention(app.ObjectRetentionRequest{
		TenantID:      "ten_1",
		ObjectPrefix:  "tenants/ten_1/raw/",
		ObjectKey:     "tenants/ten_1/raw/sample.json",
		Mode:          "compliance",
		RetentionDays: 30,
	}, true, &mode, &validity, &unit, &mode, &retainUntil, now)
	if !result.Enforced {
		t.Fatalf("expected object-level enforced retention: %#v", result)
	}
	if len(result.Checks) != 7 {
		t.Fatalf("checks = %#v", result.Checks)
	}
}

func TestRetentionDaysConvertsYears(t *testing.T) {
	validity := uint(2)
	unit := minio.Years
	if got := retentionDays(&validity, &unit); got != uint(730) {
		t.Fatalf("retention days = %d", got)
	}
}
