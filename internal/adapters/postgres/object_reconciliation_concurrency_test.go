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

func TestApplyObjectReconciliationRejectsStaleLifecycleSnapshot(t *testing.T) {
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

	schema := "evydence_reconcile_stale_" + strings.ReplaceAll(
		time.Now().UTC().Format("20060102150405.000000000"), ".", "_",
	)
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.pool.Exec(
			context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE",
		)
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
		ID: "ten_reconcile_stale", Name: "Reconcile stale", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	payload := app.ObjectPayload{
		TenantID:  "ten_reconcile_stale",
		Digest:    "sha256:" + strings.Repeat("c", 64),
		Size:      7,
		MediaType: "application/octet-stream",
		StagingKey: "tenants/ten_reconcile_stale/staging/sha256/" +
			strings.Repeat("c", 64),
		FinalKey: "tenants/ten_reconcile_stale/payloads/sha256/" +
			strings.Repeat("c", 64),
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

	// Model a worker finalizing the payload after reconciliation scanned the
	// staged row but before it attempted to apply its stale orphan decision.
	if err := store.MarkObjectPayloadFinalized(ctx, payload); err != nil {
		t.Fatalf("concurrent finalization: %v", err)
	}

	receipt := app.ObjectReconciliationReceipt{
		ID:                     "rec_stale_snapshot",
		SchemaVersion:          app.ObjectReconciliationReceiptSchemaVersion,
		TenantID:               payload.TenantID,
		DryRun:                 false,
		ScannedPayloads:        1,
		MissingStagedObjects:   1,
		QuarantinedPayloads:    1,
		CreatedAt:              now.Add(time.Minute),
	}
	err = store.ApplyObjectReconciliation(
		ctx,
		receipt,
		[]app.ObjectPayloadReconciliationAction{{
			Payload: payload,
			Status:  app.ObjectPayloadOrphaned,
		}},
	)
	if !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale reconciliation err=%v, want conflict", err)
	}

	stored, err := store.GetObjectPayload(ctx, payload.TenantID, payload.Digest)
	if err != nil {
		t.Fatalf("load payload after stale reconciliation: %v", err)
	}
	if stored.Status != app.ObjectPayloadFinalized {
		t.Fatalf("stale reconciliation changed status to %q", stored.Status)
	}

	var receiptCount, actionAuditCount int
	if err := store.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM object_reconciliation_receipts WHERE id = $1`,
		receipt.ID,
	).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM audit_chain_entries
		WHERE tenant_id = $1
		  AND entry_type = 'object_payload.reconciliation_action'
	`, payload.TenantID).Scan(&actionAuditCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 0 || actionAuditCount != 0 {
		t.Fatalf(
			"stale reconciliation persisted receipt/audit counts %d/%d",
			receiptCount, actionAuditCount,
		)
	}
}
