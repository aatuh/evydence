package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

func reconciliationCoveragePayload(now time.Time) app.ObjectPayload {
	digestHex := strings.Repeat("d", 64)
	return app.ObjectPayload{
		TenantID:   "ten_reconcile_coverage",
		Digest:     "sha256:" + digestHex,
		Size:       7,
		MediaType:  "application/octet-stream",
		StagingKey: "tenants/ten_reconcile_coverage/staging/sha256/" + digestHex,
		FinalKey:   "tenants/ten_reconcile_coverage/payloads/sha256/" + digestHex,
		Status:     app.ObjectPayloadStaged,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

func reconciliationCoverageReceipt(now time.Time) app.ObjectReconciliationReceipt {
	return app.ObjectReconciliationReceipt{
		ID:            "rec_coverage_edges",
		SchemaVersion: app.ObjectReconciliationReceiptSchemaVersion,
		TenantID:      "ten_reconcile_coverage",
		DryRun:        false,
		CreatedAt:     now,
	}
}

func TestObjectReconciliationValidationEdgesFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 8, 9, 30, 0, 0, time.UTC)
	payload := reconciliationCoveragePayload(now)
	receipt := reconciliationCoverageReceipt(now)
	var store *Store

	if _, err := store.GetObjectPayload(t.Context(), payload.TenantID, payload.Digest); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil store GetObjectPayload err=%v", err)
	}
	if err := store.MarkObjectPayloadFinalized(t.Context(), payload); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil store finalize err=%v", err)
	}
	if err := store.MarkObjectPayloadFailed(t.Context(), payload, "reconciliation_mismatch"); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil store fail err=%v", err)
	}
	if _, _, err := store.ListObjectPayloads(t.Context(), payload.TenantID, 0, 1); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil store list err=%v", err)
	}
	if _, err := store.ObjectPayloadOwnsObject(t.Context(), payload.TenantID, payload.FinalKey); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil store ownership err=%v", err)
	}
	if err := store.RecordObjectReconciliationReceipt(t.Context(), receipt); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil store receipt err=%v", err)
	}
	if _, err := store.ObjectReconciliationMetrics(t.Context(), payload.TenantID); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil store metrics err=%v", err)
	}
	if err := store.MarkObjectPayloadOrphaned(t.Context(), payload); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil store orphan err=%v", err)
	}
	if err := store.ApplyObjectReconciliation(t.Context(), receipt, nil); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil store atomic apply err=%v", err)
	}

	if validObjectPayloadFailureCode("") {
		t.Fatal("empty failure code accepted")
	}
	if validObjectPayloadFailureCode(strings.Repeat("a", 97)) {
		t.Fatal("oversized failure code accepted")
	}
	if validObjectPayloadFailureCode("Bad-Code") {
		t.Fatal("unsafe failure code accepted")
	}
	if !validObjectPayloadFailureCode("safe_code_1") {
		t.Fatal("safe failure code rejected")
	}
	if validObjectReconciliationReceipt(app.ObjectReconciliationReceipt{}) {
		t.Fatal("empty receipt accepted")
	}
	negative := receipt
	negative.ProviderOrphans = -1
	if validObjectReconciliationReceipt(negative) {
		t.Fatal("negative receipt counter accepted")
	}
	if got := nullableReconciliationCursor(7); got != 7 {
		t.Fatalf("nonzero cursor=%v", got)
	}

	finalized := app.ObjectPayloadReconciliationAction{Payload: payload, Status: app.ObjectPayloadFinalized}
	failed := app.ObjectPayloadReconciliationAction{Payload: payload, Status: app.ObjectPayloadFailed, FailureCode: "reconciliation_mismatch"}
	if !validObjectReconciliationAction(finalized) || !validObjectReconciliationAction(failed) {
		t.Fatal("valid reconciliation transition rejected")
	}
	invalidFailed := failed
	invalidFailed.FailureCode = "other"
	if validObjectReconciliationAction(invalidFailed) {
		t.Fatal("invalid failed reconciliation transition accepted")
	}
	if validObjectReconciliationAction(app.ObjectPayloadReconciliationAction{Payload: payload}) {
		t.Fatal("unknown reconciliation transition accepted")
	}
	if err := applyObjectReconciliationAction(t.Context(), nil, receipt, app.ObjectPayloadReconciliationAction{Payload: payload}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("unknown apply transition err=%v", err)
	}
}

func TestObjectReconciliationCanceledDatabaseOperationsFailClosed(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	store, err := Open(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC().Round(0)
	payload := reconciliationCoveragePayload(now)
	receipt := reconciliationCoverageReceipt(now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := store.GetObjectPayload(ctx, payload.TenantID, payload.Digest); err == nil {
		t.Fatal("canceled payload lookup succeeded")
	}
	if err := store.MarkObjectPayloadFinalized(ctx, payload); err == nil {
		t.Fatal("canceled finalization succeeded")
	}
	if err := store.MarkObjectPayloadFailed(ctx, payload, "reconciliation_mismatch"); err == nil {
		t.Fatal("canceled failure transition succeeded")
	}
	if _, _, err := store.ListObjectPayloads(ctx, payload.TenantID, 0, 1); err == nil {
		t.Fatal("canceled reconciliation list succeeded")
	}
	if _, err := store.ObjectPayloadOwnsObject(ctx, payload.TenantID, payload.FinalKey); err == nil {
		t.Fatal("canceled ownership lookup succeeded")
	}
	if err := store.RecordObjectReconciliationReceipt(ctx, receipt); err == nil {
		t.Fatal("canceled receipt write succeeded")
	}
	if _, err := store.ObjectReconciliationMetrics(ctx, payload.TenantID); err == nil {
		t.Fatal("canceled metrics lookup succeeded")
	}
	if err := store.MarkObjectPayloadOrphaned(ctx, payload); err == nil {
		t.Fatal("canceled orphan transition succeeded")
	}
	if err := store.ApplyObjectReconciliation(ctx, receipt, []app.ObjectPayloadReconciliationAction{{
		Payload: payload,
		Status:  app.ObjectPayloadOrphaned,
	}}); err == nil {
		t.Fatal("canceled atomic reconciliation apply succeeded")
	}
}
