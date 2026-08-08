package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestApplyObjectReconciliationRollsBackLifecycleWhenReceiptInsertFails(t *testing.T) {
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
	schema := "evydence_reconcile_atomic_" + strings.ReplaceAll(
		time.Now().UTC().Format("20060102150405.000000000"), ".", "_",
	)
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.pool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
	}()
	store, err := OpenWithOptions(
		ctx,
		databaseURLWithSearchPath(t, databaseURL, schema),
		StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true},
	)
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
	if err := seed.Repositories().Identity.InsertTenant(ctx, domain.Tenant{
		ID: "ten_reconcile_atomic", Name: "Reconcile atomic", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	payload := app.ObjectPayload{
		TenantID:  "ten_reconcile_atomic",
		Digest:    "sha256:" + strings.Repeat("b", 64),
		Size:      7,
		MediaType: "application/octet-stream",
		StagingKey: "tenants/ten_reconcile_atomic/staging/sha256/" +
			strings.Repeat("b", 64),
		FinalKey: "tenants/ten_reconcile_atomic/payloads/sha256/" +
			strings.Repeat("b", 64),
		Status:    app.ObjectPayloadStaged,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := seed.Repositories().Payloads.RecordStagedObjectPayload(ctx, payload); err != nil {
		t.Fatal(err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	blockingReceipt := app.ObjectReconciliationReceipt{
		ID:            "rec_atomic_rollback",
		SchemaVersion: app.ObjectReconciliationReceiptSchemaVersion,
		TenantID:      payload.TenantID,
		DryRun:        true,
		CreatedAt:     now,
	}
	if err := store.RecordObjectReconciliationReceipt(ctx, blockingReceipt); err != nil {
		t.Fatalf("seed blocking receipt: %v", err)
	}

	applyReceipt := blockingReceipt
	applyReceipt.DryRun = false
	applyReceipt.ScannedPayloads = 1
	applyReceipt.MissingStagedObjects = 1
	applyReceipt.QuarantinedPayloads = 1
	err = store.ApplyObjectReconciliation(
		ctx,
		applyReceipt,
		[]app.ObjectPayloadReconciliationAction{{
			Payload: payload,
			Status:  app.ObjectPayloadOrphaned,
		}},
	)
	if err == nil {
		t.Fatal("duplicate receipt did not fail atomic apply")
	}

	stored, err := store.GetObjectPayload(ctx, payload.TenantID, payload.Digest)
	if err != nil {
		t.Fatalf("load payload after failed atomic apply: %v", err)
	}
	if stored.Status != app.ObjectPayloadStaged {
		t.Fatalf("failed receipt insert left payload status %q, want staged", stored.Status)
	}
	var receiptCount, auditCount int
	if err := store.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM object_reconciliation_receipts WHERE id = $1`,
		blockingReceipt.ID,
	).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_chain_entries WHERE tenant_id = $1 AND entry_type = 'object_payload.reconciled'`,
		payload.TenantID,
	).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 1 || auditCount != 1 {
		t.Fatalf("failed atomic apply receipt_count=%d audit_count=%d, want 1/1", receiptCount, auditCount)
	}
}
