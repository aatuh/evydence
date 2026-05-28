package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	fsobject "github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestStoreLoadSaveAndOutboxWithPostgres(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	state := app.PersistedState{
		Tenants: map[string]domain.Tenant{
			"ten_test": {ID: "ten_test", Name: "Test", CreatedAt: time.Now().UTC()},
		},
		Organizations: map[string]domain.Organization{
			"org_test": {ID: "org_test", TenantID: "ten_test", Name: "Org", Slug: "org", Status: "active", SchemaVersion: domain.OrganizationSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Users: map[string]domain.HumanUser{
			"user_test": {ID: "user_test", TenantID: "ten_test", OrganizationID: "org_test", Email: "user@example.test", DisplayName: "User", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		RoleBindings: map[string]domain.RoleBinding{
			"rb_test": {ID: "rb_test", TenantID: "ten_test", SubjectType: "user", SubjectID: "user_test", Role: "security_engineer", SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		APIKeys: map[string]domain.APIKey{
			"key_test": {ID: "key_test", TenantID: "ten_test", Name: "api", Prefix: "evy_test", Scopes: []string{"evidence:write"}, CreatedAt: time.Now().UTC()},
		},
		APIKeyHashes: map[string]string{"key_test": "hmac-test-hash"},
		SSOProviders: map[string]domain.SSOProvider{
			"sso_test": {ID: "sso_test", TenantID: "ten_test", Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client", Status: "active", JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "kid-1", "crv": "Ed25519", "x": "abc"}}}, SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: time.Now().UTC(), TrustMaterialUpdatedAt: ptrTime(time.Now().UTC())},
		},
		IdentityLinks: map[string]domain.UserIdentityLink{
			"link_test": {ID: "link_test", TenantID: "ten_test", UserID: "user_test", ProviderID: "sso_test", Subject: "sub", Email: "user@example.test", Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: time.Now().UTC()},
		},
		SSOSessions: map[string]domain.SSOSession{
			"sess_test": {ID: "sess_test", TenantID: "ten_test", UserID: "user_test", ProviderID: "sso_test", Prefix: "sess", ExpiresAt: time.Now().UTC().Add(time.Hour), SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		SSOSessionHashes: map[string]string{"sess_test": "session-hash"},
		Idempotency: map[string]app.IdempotencyRecord{
			app.NewIdempotencyRecordKey("ten_test", "user:user_test", "POST", "/v1/products", "idem"): {RequestHash: "sha256:request", Status: 201, Response: map[string]any{"ok": true}, CreatedAt: time.Now().UTC()},
		},
	}
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LoadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.Tenants["ten_test"].ID != "ten_test" {
		t.Fatalf("unexpected loaded state: ok=%v state=%#v", ok, got.Tenants)
	}
	var indexed int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM resource_index WHERE tenant_id = 'ten_test' AND resource_type = 'tenant'`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != 1 {
		t.Fatalf("resource index rows = %d, want 1", indexed)
	}
	var apiKeyHash string
	if err := store.pool.QueryRow(ctx, `SELECT hash FROM api_keys WHERE id = 'key_test' AND tenant_id = 'ten_test'`).Scan(&apiKeyHash); err != nil {
		t.Fatal(err)
	}
	if apiKeyHash != "hmac-test-hash" {
		t.Fatalf("api key hash = %q", apiKeyHash)
	}
	var userRows int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM human_users WHERE tenant_id = 'ten_test' AND email = 'user@example.test'`).Scan(&userRows); err != nil {
		t.Fatal(err)
	}
	if userRows != 1 {
		t.Fatalf("human user rows = %d, want 1", userRows)
	}
	var ssoTrustRows int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM sso_providers WHERE id = 'sso_test' AND trust_material_updated_at IS NOT NULL AND jwks <> '{}'::jsonb`).Scan(&ssoTrustRows); err != nil {
		t.Fatal(err)
	}
	if ssoTrustRows != 1 {
		t.Fatalf("sso trust rows = %d, want 1", ssoTrustRows)
	}
	var idemActor string
	if err := store.pool.QueryRow(ctx, `SELECT actor_key_id FROM idempotency_records WHERE tenant_id = 'ten_test' AND idempotency_key = 'idem'`).Scan(&idemActor); err != nil {
		t.Fatal(err)
	}
	if idemActor != "user:user_test" {
		t.Fatalf("idempotency actor = %q", idemActor)
	}
	job := app.OutboxJob{ID: "job_test_" + time.Now().Format("150405.000000000"), TenantID: "ten_test", Kind: "verify_subject", SubjectType: "audit_chain", SubjectID: "audit_chain", CreatedAt: time.Now().UTC()}
	if err := store.Enqueue(ctx, job); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.ClaimJobs(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) == 0 {
		t.Fatal("expected claimed job")
	}
	if err := store.CompleteJob(ctx, jobs[0].ID); err != nil {
		t.Fatal(err)
	}

	retryJob := app.OutboxJob{ID: "job_retry_" + time.Now().Format("150405.000000000"), TenantID: "ten_test", Kind: "parse_sbom", SubjectType: "sbom", SubjectID: "sbom_test", CreatedAt: time.Now().UTC()}
	if err := store.Enqueue(ctx, retryJob); err != nil {
		t.Fatal(err)
	}
	if pending, err := store.CountPendingJobs(ctx); err != nil {
		t.Fatal(err)
	} else if pending == 0 {
		t.Fatal("expected pending outbox job")
	}
	claimed, err := store.ClaimJobs(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) == 0 {
		t.Fatal("expected retry job claim")
	}
	if err := store.FailJob(ctx, claimed[0].ID, context.Canceled); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Now(ctx); err != nil {
		t.Fatal(err)
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func TestPendingMigrationVersionsWithPostgres(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	baseStore, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer baseStore.Close()
	schema := "evydence_pending_migrations_" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := baseStore.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = baseStore.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, schema))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pending, err := store.PendingMigrationVersions(ctx, "../../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	names := migrationFileNames(t, "../../../migrations")
	if len(pending) != len(names) {
		t.Fatalf("pending migrations = %d, want %d", len(pending), len(names))
	}
	if err := store.RequireNoPendingMigrations(ctx, "../../../migrations"); err == nil {
		t.Fatal("expected pending migrations to fail closed")
	}
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	pending, err = store.PendingMigrationVersions(ctx, "../../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending after apply = %#v", pending)
	}
	if err := store.RequireNoPendingMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("require no pending after apply: %v", err)
	}
}

func TestPostgresBackupRestoreRehearsalPreservesLedgerAndObjects(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	baseStore, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer baseStore.Close()
	sourceSchema := "evydence_restore_source_" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "_")
	targetSchema := "evydence_restore_target_" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "_")
	for _, schema := range []string{sourceSchema, targetSchema} {
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, err := baseStore.pool.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
			t.Fatal(err)
		}
		defer func(schema string) {
			_, _ = baseStore.pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		}(schema)
	}

	sourceStore, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, sourceSchema))
	if err != nil {
		t.Fatal(err)
	}
	defer sourceStore.Close()
	if _, err := sourceStore.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	sourceObjectRoot := t.TempDir()
	sourceObjects, err := fsobject.New(sourceObjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := app.NewLedgerWithError(app.Config{APIKeyPepper: "test-pepper", Store: sourceStore, ObjectStore: sourceObjects})
	if err != nil {
		t.Fatal(err)
	}
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Restore Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments-restore")
	if err != nil {
		t.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "payments.tar.gz", "application/gzip", "sha256:"+strings.Repeat("a", 64), 42)
	if err != nil {
		t.Fatal(err)
	}
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:oci/api"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ledger.GenerateBackupManifest(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	dbBackup, ok, err := sourceStore.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load backup state ok=%v err=%v", ok, err)
	}

	targetStore, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, targetSchema))
	if err != nil {
		t.Fatal(err)
	}
	defer targetStore.Close()
	if _, err := targetStore.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	if err := targetStore.SaveState(ctx, dbBackup); err != nil {
		t.Fatal(err)
	}
	targetObjectRoot := t.TempDir()
	copyTree(t, sourceObjectRoot, targetObjectRoot)
	targetObjects, err := fsobject.New(targetObjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := app.NewLedgerWithError(app.Config{APIKeyPepper: "test-pepper", Store: targetStore, ObjectStore: targetObjects})
	if err != nil {
		t.Fatal(err)
	}
	restoredActor, err := restored.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.VerifyBackupManifest(ctx, restoredActor, manifest.ID); err != nil {
		t.Fatalf("verify backup manifest after restore: %v", err)
	}
	restoredSBOM, err := restored.GetSBOM(ctx, restoredActor, sbom.ID)
	if err != nil || restoredSBOM.ComponentCount != sbom.ComponentCount {
		t.Fatalf("restored sbom = %#v err=%v", restoredSBOM, err)
	}
	evidence, err := restored.GetEvidence(ctx, restoredActor, restoredSBOM.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	objectKey := strings.TrimPrefix(evidence.PayloadRef, "object://")
	object, err := targetObjects.Get(ctx, objectKey)
	if err != nil {
		t.Fatalf("restored object: %v", err)
	}
	if object.Digest != evidence.PayloadHash {
		t.Fatalf("restored object digest = %q, want %q", object.Digest, evidence.PayloadHash)
	}
	if vr, err := restored.VerifySubject(ctx, restoredActor, "release_bundle", bundle.ID); err != nil || vr.Result != "passed" {
		t.Fatalf("verify restored bundle = %#v err=%v", vr, err)
	}
}

func copyTree(t *testing.T, sourceRoot, targetRoot string) {
	t.Helper()
	if err := os.CopyFS(targetRoot, os.DirFS(sourceRoot)); err != nil {
		t.Fatal(err)
	}
}
