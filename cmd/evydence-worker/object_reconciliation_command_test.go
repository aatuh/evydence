package main

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestRunObjectReconciliationDryRunAndApplyWithLivePostgres(t *testing.T) {
	baseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer admin.Close(ctx)

	schema := "evydence_worker_reconcile_" + strings.ReplaceAll(
		time.Now().UTC().Format("20060102150405.000000000"), ".", "_",
	)
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	defer func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}()

	databaseURL := postgresURLWithSearchPath(t, baseURL, schema)
	store, err := postgres.OpenWithOptions(ctx, databaseURL, postgres.StoreOptions{
		LoadMode:              postgres.LoadModeRelationalOnly,
		DisableSnapshotWrites: true,
	})
	if err != nil {
		t.Fatalf("open scoped postgres: %v", err)
	}
	if _, err := store.ApplyMigrations(ctx, "../../migrations"); err != nil {
		store.Close()
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Now().UTC().Round(0)
	tenantID := "ten_worker_reconcile"
	digest := "sha256:" + strings.Repeat("a", 64)
	payload := app.ObjectPayload{
		TenantID:   tenantID,
		Digest:     digest,
		Size:       7,
		MediaType:  "application/octet-stream",
		StagingKey: "tenants/" + tenantID + "/staging/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		FinalKey:   "tenants/" + tenantID + "/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		Status:     app.ObjectPayloadStaged,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	uow, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		store.Close()
		t.Fatalf("begin seed transaction: %v", err)
	}
	if err := uow.Repositories().Identity.InsertTenant(ctx, domain.Tenant{
		ID: tenantID, Name: "Worker reconciliation", CreatedAt: now,
	}); err != nil {
		_ = uow.Rollback(ctx)
		store.Close()
		t.Fatalf("insert tenant: %v", err)
	}
	if err := uow.Repositories().Payloads.RecordStagedObjectPayload(ctx, payload); err != nil {
		_ = uow.Rollback(ctx)
		store.Close()
		t.Fatalf("insert staged payload metadata: %v", err)
	}
	if err := uow.Commit(ctx); err != nil {
		store.Close()
		t.Fatalf("commit seed transaction: %v", err)
	}
	store.Close()

	t.Setenv("ENV", "")
	t.Setenv("EVYDENCE_DATABASE_URL", databaseURL)
	t.Setenv("EVYDENCE_POSTGRES_LOAD_MODE", "relational_only")
	t.Setenv("EVYDENCE_MIGRATIONS_DIR", "../../migrations")
	t.Setenv("EVYDENCE_SKIP_MIGRATIONS", "true")
	t.Setenv("EVYDENCE_OBJECT_STORE", "filesystem")
	t.Setenv("EVYDENCE_OBJECT_DIR", t.TempDir())

	if err := runObjectReconciliation([]string{
		"--tenant", tenantID,
		"--limit", "10",
		"--provider-limit", "10",
	}); err != nil {
		t.Fatalf("dry-run reconciliation: %v", err)
	}
	if err := runObjectReconciliation([]string{
		"--tenant", tenantID,
		"--limit", "10",
		"--provider-limit", "10",
		"--apply",
		"--orphan-staged-after", "1h",
	}); err != nil {
		t.Fatalf("apply reconciliation: %v", err)
	}

	verifyStore, err := postgres.OpenWithOptions(ctx, databaseURL, postgres.StoreOptions{
		LoadMode:              postgres.LoadModeRelationalOnly,
		DisableSnapshotWrites: true,
	})
	if err != nil {
		t.Fatalf("reopen scoped postgres: %v", err)
	}
	defer verifyStore.Close()
	if _, err := verifyStore.GetObjectPayload(ctx, tenantID, digest); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("orphaned payload reader gate err=%v, want not found", err)
	}
	metrics, err := verifyStore.ObjectReconciliationMetrics(ctx, tenantID)
	if err != nil {
		t.Fatalf("read reconciliation metrics: %v", err)
	}
	if metrics.Runs != 2 || metrics.ScannedPayloads != 2 || metrics.MissingStagedObjects != 2 || metrics.QuarantinedPayloads != 1 {
		t.Fatalf("unexpected reconciliation metrics: %#v", metrics)
	}

	queryConn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect scoped postgres for audit verification: %v", err)
	}
	defer queryConn.Close(ctx)
	var runAudits, actionAudits int
	if err := queryConn.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM audit_chain_entries
		WHERE tenant_id = $1 AND entry_type = 'object_payload.reconciled'
	`, tenantID).Scan(&runAudits); err != nil {
		t.Fatalf("count reconciliation audits: %v", err)
	}
	if err := queryConn.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM audit_chain_entries
		WHERE tenant_id = $1 AND entry_type = 'object_payload.reconciliation_action'
	`, tenantID).Scan(&actionAudits); err != nil {
		t.Fatalf("count reconciliation action audits: %v", err)
	}
	if runAudits != 2 || actionAudits != 1 {
		t.Fatalf("reconciliation audit counts=%d/%d, want 2/1", runAudits, actionAudits)
	}
}

func TestRunObjectReconciliationRejectsUnsafeRuntimeConfiguration(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://unused.invalid/evydence")
	t.Setenv("EVYDENCE_POSTGRES_LOAD_MODE", "not-a-load-mode")
	if err := runObjectReconciliation([]string{"--tenant", "ten_runtime"}); err == nil {
		t.Fatal("invalid postgres load mode was accepted")
	}

	t.Setenv("ENV", "production")
	t.Setenv("EVYDENCE_POSTGRES_LOAD_MODE", "snapshot_preferred")
	if err := runObjectReconciliation([]string{"--tenant", "ten_runtime"}); err == nil {
		t.Fatal("unsafe production load mode was accepted")
	}

	t.Setenv("ENV", "")
	t.Setenv("EVYDENCE_POSTGRES_LOAD_MODE", "relational_only")
	if err := runObjectReconciliation([]string{"--tenant", "ten_runtime"}); err == nil || !strings.Contains(err.Error(), "durable storage") {
		t.Fatalf("unreachable database err=%v", err)
	}
}

func postgresURLWithSearchPath(t *testing.T, rawURL, schema string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse postgres URL: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
