package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestStoreObjectPayloadLifecycleIsTenantScopedAndDeduplicated(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_object_payloads_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.pool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") }()
	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Now().UTC().Round(0)
	seed, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Repositories().Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_payload", Name: "Payload tenant", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	payload := app.ObjectPayload{
		TenantID:   "ten_payload",
		Digest:     digest,
		Size:       42,
		MediaType:  "application/json",
		StagingKey: "tenants/ten_payload/staging/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		FinalKey:   "tenants/ten_payload/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		Status:     app.ObjectPayloadStaged,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	write, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := write.Repositories().Payloads.RecordStagedObjectPayload(ctx, payload); err != nil {
		t.Fatal(err)
	}
	if err := write.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	stored, err := store.GetObjectPayload(ctx, payload.TenantID, payload.Digest)
	if err != nil || stored.Status != app.ObjectPayloadStaged || stored.StagingKey != payload.StagingKey || stored.FinalKey != payload.FinalKey {
		t.Fatalf("staged payload=%#v err=%v", stored, err)
	}
	if _, err := store.GetObjectPayload(ctx, "ten_other", payload.Digest); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("cross-tenant payload lookup err=%v, want not found", err)
	}
	if err := store.MarkObjectPayloadFinalized(ctx, payload); err != nil {
		t.Fatalf("mark finalized: %v", err)
	}
	stored, err = store.GetObjectPayload(ctx, payload.TenantID, payload.Digest)
	if err != nil || stored.Status != app.ObjectPayloadFinalized || stored.FinalizedAt == nil {
		t.Fatalf("finalized payload=%#v err=%v", stored, err)
	}
	if err := store.MarkObjectPayloadFailed(ctx, payload, "finalization_failed"); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("finalized payload failure transition err=%v, want conflict", err)
	}
	if err := store.MarkObjectPayloadFailed(ctx, payload, "reconciliation_mismatch"); err != nil {
		t.Fatalf("reconciliation mismatch must quarantine a finalized payload: %v", err)
	}
	stored, err = store.GetObjectPayload(ctx, payload.TenantID, payload.Digest)
	if err != nil || stored.Status != app.ObjectPayloadFailed || stored.FailureCode != "reconciliation_mismatch" {
		t.Fatalf("reconciliation failure transition=%#v err=%v", stored, err)
	}

	duplicate := payload
	duplicate.StagingKey = "tenants/ten_payload/staging/sha256/duplicate"
	duplicate.FinalKey = "tenants/ten_payload/payloads/sha256/duplicate"
	write, err = store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = write.Repositories().Payloads.RecordStagedObjectPayload(ctx, duplicate)
	if !errors.Is(err, app.ErrConflict) {
		_ = write.Rollback(ctx)
		t.Fatalf("same-tenant digest dedup error=%v, want conflict", err)
	}
	if err := write.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkObjectPayloadOrphaned(ctx, payload); err != nil {
		t.Fatalf("mark orphaned: %v", err)
	}
	if _, err := store.GetObjectPayload(ctx, payload.TenantID, payload.Digest); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("orphaned payload reader gate err=%v, want not found", err)
	}
	page, next, err := store.ListObjectPayloads(ctx, payload.TenantID, 0, 10)
	if err != nil || next != 0 || len(page) != 1 || page[0].Status != app.ObjectPayloadOrphaned {
		t.Fatalf("reconciliation payload page=%#v next=%d err=%v", page, next, err)
	}
	owned, err := store.ObjectPayloadOwnsObject(ctx, payload.TenantID, payload.FinalKey)
	if err != nil || !owned {
		t.Fatalf("orphaned payload ownership=%t err=%v", owned, err)
	}
	receipt := app.ObjectReconciliationReceipt{
		ID:                  "rec_payload_lifecycle_test",
		SchemaVersion:       app.ObjectReconciliationReceiptSchemaVersion,
		TenantID:            payload.TenantID,
		DryRun:              true,
		ScannedPayloads:     1,
		MissingFinalObjects: 1,
		CreatedAt:           now,
	}
	if err := store.RecordObjectReconciliationReceipt(ctx, receipt); err != nil {
		t.Fatalf("record reconciliation receipt: %v", err)
	}
	metrics, err := store.ObjectReconciliationMetrics(ctx, payload.TenantID)
	if err != nil || metrics.Runs != 1 || metrics.ScannedPayloads != 1 || metrics.MissingFinalObjects != 1 || metrics.LastRunAt.IsZero() {
		t.Fatalf("reconciliation metrics=%#v err=%v", metrics, err)
	}
	var auditCount int
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_chain_entries WHERE tenant_id = $1 AND entry_type = 'object_payload.reconciled'`, payload.TenantID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("reconciliation audit count=%d err=%v", auditCount, err)
	}
}
