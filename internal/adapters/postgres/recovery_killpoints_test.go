package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	fsobject "github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestRecoveryKillPointsFailClosedAndResume(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_recovery_kill_" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.pool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") }()

	scopedURL := databaseURLWithSearchPath(t, databaseURL, schema)
	store, err := OpenWithOptions(ctx, scopedURL, StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	now := time.Now().UTC().Round(0)
	tenantID := "ten_recovery_kill"
	seed, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Repositories().Identity.InsertTenant(ctx, domain.Tenant{ID: tenantID, Name: "Recovery kill points", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	objects, err := fsobject.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	body := []byte("kill-point-payload")
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	stagingKey, finalKey, err := app.CanonicalObjectPayloadKeys(tenantID, digest)
	if err != nil {
		t.Fatal(err)
	}
	payload := app.ObjectPayload{TenantID: tenantID, Digest: digest, MediaType: "application/octet-stream", StagingKey: stagingKey, FinalKey: finalKey, Status: app.ObjectPayloadStaged, CreatedAt: now, UpdatedAt: now}
	payload, err = objects.StagePayload(ctx, payload, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	// Kill after upload: provider bytes exist without database ownership. Dry-run
	// reconciliation reports the orphan candidate and never deletes it.
	uploadReceipt, err := app.ReconcileObjectPayloads(ctx, store, store, objects, app.ObjectReconciliationRequest{TenantID: tenantID, Limit: 10, ProviderInventoryLimit: 10, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if uploadReceipt.ScannedPayloads != 0 || uploadReceipt.ProviderOrphans != 1 {
		t.Fatalf("upload kill-point receipt=%#v", uploadReceipt)
	}
	if _, err := objects.Get(ctx, payload.StagingKey); err != nil {
		t.Fatalf("upload kill-point deleted staged object: %v", err)
	}

	// Kill after metadata commit: metadata and its finalizer job commit together;
	// the staged object remains healthy and resumable.
	metadata, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := metadata.Repositories().Payloads.RecordStagedObjectPayload(ctx, payload); err != nil {
		t.Fatal(err)
	}
	finalizeJob := app.OutboxJob{ID: "job_recovery_finalize", TenantID: tenantID, Kind: "finalize_payload", SubjectType: "object_payload", SubjectID: digest, CreatedAt: now, Payload: map[string]any{"payload_digest": digest, "payload_lifecycle": app.PayloadLifecycleVersion}}
	if err := metadata.Repositories().Outbox.Enqueue(ctx, finalizeJob); err != nil {
		t.Fatal(err)
	}
	if err := metadata.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	metadataReceipt, err := app.ReconcileObjectPayloads(ctx, store, store, objects, app.ObjectReconciliationRequest{TenantID: tenantID, Limit: 10, ProviderInventoryLimit: 10, Now: func() time.Time { return now.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	if metadataReceipt.ScannedPayloads != 1 || metadataReceipt.HealthyPayloads != 1 || metadataReceipt.QuarantinedPayloads != 0 {
		t.Fatalf("metadata kill-point receipt=%#v", metadataReceipt)
	}
	var queuedStatus string
	if err := store.pool.QueryRow(ctx, `SELECT status FROM outbox_jobs WHERE id=$1`, finalizeJob.ID).Scan(&queuedStatus); err != nil || queuedStatus != "queued" {
		t.Fatalf("metadata kill-point finalizer status=%q err=%v", queuedStatus, err)
	}

	// Kill after provider finalization but before database lifecycle transition:
	// apply-mode reconciliation observes the verified final object and advances
	// the stale metadata exactly once.
	if _, err := objects.FinalizePayload(ctx, payload); err != nil {
		t.Fatal(err)
	}
	finalReceipt, err := app.ReconcileObjectPayloads(ctx, store, store, objects, app.ObjectReconciliationRequest{TenantID: tenantID, Limit: 10, ProviderInventoryLimit: 10, Apply: true, OrphanStagedAfter: time.Hour, Now: func() time.Time { return now.Add(2 * time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	if finalReceipt.RecoveredFinalizations != 1 {
		t.Fatalf("finalization kill-point receipt=%#v", finalReceipt)
	}
	stored, err := store.GetObjectPayload(ctx, tenantID, digest)
	if err != nil || stored.Status != app.ObjectPayloadFinalized {
		t.Fatalf("recovered payload=%#v err=%v", stored, err)
	}

	// Kill after an audit append while its unit-of-work transaction is still
	// open: connection loss/rollback cannot publish a half-committed audit entry.
	auditTx, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auditID := "ace_recovery_kill_rollback"
	if _, err := auditTx.Repositories().Audit.Append(ctx, domain.AuditChainEntry{ID: auditID, TenantID: tenantID, EntryType: "recovery.kill_point", SubjectType: "object_payload", SubjectID: digest, ActorType: "worker", ActorID: "recovery-test", OccurredAt: now.Add(3 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := auditTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries WHERE id=$1`, auditID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("rolled-back audit count=%d err=%v", auditCount, err)
	}

	// Kill after outbox claim: the lease is durable, stale completion is fenced,
	// and a restarted store can reclaim the expired lease with a new token.
	claimed, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(claimed) != 1 || claimed[0].ID != finalizeJob.ID {
		t.Fatalf("claim kill-point job=%#v err=%v", claimed, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE outbox_jobs SET locked_at=now()-interval '6 minutes' WHERE id=$1`, finalizeJob.ID); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithOptions(ctx, scopedURL, StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reclaimed, err := reopened.ClaimJobs(ctx, 1)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].ID != finalizeJob.ID || reclaimed[0].LeaseToken == claimed[0].LeaseToken || reclaimed[0].Attempts != 2 {
		t.Fatalf("reclaimed kill-point job=%#v err=%v", reclaimed, err)
	}
	if err := reopened.CompleteJob(ctx, claimed[0].ID, claimed[0].LeaseToken); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale pre-crash lease completion err=%v, want conflict", err)
	}
	if err := reopened.CompleteJob(ctx, reclaimed[0].ID, reclaimed[0].LeaseToken); err != nil {
		t.Fatalf("complete reclaimed job: %v", err)
	}
}
