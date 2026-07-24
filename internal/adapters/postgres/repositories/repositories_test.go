package repositories_test

import (
	"context"
	"errors"
	"math"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestRepositoriesWriteBoundedContextsInOneTransaction(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	repositories := postgresrepositories.New(tx)
	now := time.Now().UTC().Round(0)
	tenant := domain.Tenant{ID: "ten_repository", Name: "Repository tenant", CreatedAt: now}
	if err := repositories.Identity.InsertTenant(ctx, tenant); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := repositories.Identity.InsertAPIKey(ctx, domain.APIKey{ID: "key_repository", TenantID: tenant.ID, Name: "repository key", Prefix: "evy_repo", Hash: "hmac-hash", Scopes: []string{"*"}, CreatedAt: now}); err != nil {
		t.Fatalf("insert API key: %v", err)
	}
	product := domain.Product{ID: "prod_repository", TenantID: tenant.ID, Name: "Repository API", Slug: "repository-api", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	project := domain.Project{ID: "proj_repository", TenantID: tenant.ID, ProductID: product.ID, Name: "Repository project", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertProject(ctx, project); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	release := domain.Release{ID: "rel_repository", TenantID: tenant.ID, ProductID: product.ID, Version: "1.0.0", State: "draft", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertRelease(ctx, release); err != nil {
		t.Fatalf("insert release: %v", err)
	}
	artifact := domain.Artifact{ID: "art_repository", TenantID: tenant.ID, Name: "repository.tgz", MediaType: "application/gzip", Digest: "sha256:repository", Size: 7, CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertArtifact(ctx, artifact); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}
	evidence := domain.EvidenceItem{
		ID: "evi_repository", TenantID: tenant.ID, ProductID: product.ID, ProjectID: project.ID, ReleaseID: release.ID,
		Type: "sbom", Title: "Repository SBOM", SourceSystem: "test", ObservedAt: now, EvidenceVersion: 1,
		SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadHash: "sha256:payload", CanonicalHash: "sha256:canonical",
		Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "untrusted", VerificationStatus: "not_verified", CreatedAt: now,
		SourceIdentity: map[string]any{"source": "repository-test"}, Metadata: map[string]any{"test": true}, Tags: []string{"test"},
	}
	if err := repositories.Evidence.InsertEvidence(ctx, evidence); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
	if err := repositories.Evidence.AppendLifecycle(ctx, domain.EvidenceLifecycleEvent{ID: "elc_repository", TenantID: tenant.ID, EvidenceID: evidence.ID, Action: "accepted", Reason: "test", ActorID: "key_repository", SchemaVersion: domain.EvidenceLifecycleSchemaVersion, CreatedAt: now, Details: map[string]any{"source": "test"}}); err != nil {
		t.Fatalf("append lifecycle: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO vulnerability_scans (id, tenant_id, evidence_id, scanner, target_ref, summary, findings, created_at)
		VALUES ('scan_repository', $1, $2, 'test', 'pkg:oci/repository', '{}'::jsonb, '[]'::jsonb, $3)
	`, tenant.ID, evidence.ID, now); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	if err := repositories.Decisions.InsertVulnerabilityDecision(ctx, domain.VulnerabilityDecision{ID: "dec_repository", TenantID: tenant.ID, FindingID: "finding_repository", ScanID: "scan_repository", ReleaseID: release.ID, Vulnerability: "CVE-2026-0001", Status: "not_affected", Justification: "test decision", Source: "test", EvidenceID: evidence.ID, SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: now, SupportingRefs: []domain.SubjectRef{}}); err != nil {
		t.Fatalf("insert decision: %v", err)
	}
	entry, err := repositories.Audit.Append(ctx, domain.AuditChainEntry{ID: "ace_repository", TenantID: tenant.ID, EntryType: "evidence.created", SubjectType: "evidence_item", SubjectID: evidence.ID, ActorType: "api_key", ActorID: "key_repository", OccurredAt: now, Metadata: map[string]any{"test": true}})
	if err != nil {
		t.Fatalf("append audit: %v", err)
	}
	if entry.Sequence != 1 || entry.EntryHash == "" {
		t.Fatalf("unexpected audit entry: %#v", entry)
	}
	if err := repositories.Idempotency.Insert(ctx, app.IdempotencyRecordKey{TenantID: tenant.ID, ActorID: "key_repository", Method: "POST", Path: "/v1/evidence", IdempotencyKey: "idem_repository"}, app.IdempotencyRecord{RequestHash: "sha256:request", Status: 201, Response: map[string]any{"id": evidence.ID}, CreatedAt: now}); err != nil {
		t.Fatalf("insert idempotency record: %v", err)
	}
	if err := repositories.Outbox.Enqueue(ctx, app.OutboxJob{ID: "job_repository", TenantID: tenant.ID, Kind: "index_evidence", SubjectType: "evidence_item", SubjectID: evidence.ID, CreatedAt: now, Payload: map[string]any{"evidence_id": evidence.ID}}); err != nil {
		t.Fatalf("enqueue outbox: %v", err)
	}
	signingKey := domain.SigningKey{ID: "sigkey_repository", TenantID: tenant.ID, KID: "repository-key", Algorithm: "Ed25519", Status: "active", PublicKey: "public", Private: []byte("encrypted-test-key"), CreatedAt: now}
	if err := repositories.Signatures.InsertSigningKey(ctx, signingKey); err != nil {
		t.Fatalf("insert signing key: %v", err)
	}
	if err := repositories.Signatures.InsertSignature(ctx, domain.Signature{ID: "sig_repository", TenantID: tenant.ID, SubjectType: "evidence_item", SubjectID: evidence.ID, KeyID: signingKey.ID, Algorithm: "Ed25519", Value: "signature", CreatedAt: now}); err != nil {
		t.Fatalf("insert signature: %v", err)
	}
	if err := repositories.Packages.InsertReleaseBundle(ctx, domain.ReleaseBundle{ID: "bundle_repository", TenantID: tenant.ID, ReleaseID: release.ID, State: "generated", Manifest: map[string]any{"release_id": release.ID}, ManifestHash: "sha256:manifest", SignatureRefs: []string{"sig_repository"}, CreatedAt: now}); err != nil {
		t.Fatalf("insert release bundle: %v", err)
	}
	if err := repositories.Verification.InsertVerificationResult(ctx, domain.VerificationResult{ID: "verify_repository", TenantID: tenant.ID, SubjectType: "evidence_item", SubjectID: evidence.ID, Result: "limited", Checks: []domain.VerifyCheck{{Name: "recorded", Result: "passed"}}, VerifiedAt: now}); err != nil {
		t.Fatalf("insert verification result: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit repository writes: %v", err)
	}
}

func TestRepositoriesRejectInvalidAndCrossTenantReferences(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	repositories := postgresrepositories.New(tx)
	now := time.Now().UTC().Round(0)
	for _, tenant := range []domain.Tenant{{ID: "ten_repository_a", Name: "A", CreatedAt: now}, {ID: "ten_repository_b", Name: "B", CreatedAt: now}} {
		if err := repositories.Identity.InsertTenant(ctx, tenant); err != nil {
			t.Fatalf("insert tenant %s: %v", tenant.ID, err)
		}
	}
	if err := repositories.ReleaseCatalog.InsertProduct(ctx, domain.Product{ID: "prod_repository_a", TenantID: "ten_repository_a", Name: "A API", Slug: "a-api", CreatedAt: now}); err != nil {
		t.Fatalf("insert tenant A product: %v", err)
	}
	if err := repositories.ReleaseCatalog.InsertProject(ctx, domain.Project{ID: "proj_repository_b", TenantID: "ten_repository_b", ProductID: "prod_repository_a", Name: "cross", CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("cross-tenant project err=%v, want not found", err)
	}
	checks := []struct {
		name string
		err  error
	}{
		{"api key", repositories.Identity.InsertAPIKey(ctx, domain.APIKey{})},
		{"product", repositories.ReleaseCatalog.InsertProduct(ctx, domain.Product{})},
		{"project", repositories.ReleaseCatalog.InsertProject(ctx, domain.Project{})},
		{"release", repositories.ReleaseCatalog.InsertRelease(ctx, domain.Release{})},
		{"artifact", repositories.ReleaseCatalog.InsertArtifact(ctx, domain.Artifact{})},
		{"evidence", repositories.Evidence.InsertEvidence(ctx, domain.EvidenceItem{})},
		{"lifecycle", repositories.Evidence.AppendLifecycle(ctx, domain.EvidenceLifecycleEvent{})},
		{"decision", repositories.Decisions.InsertVulnerabilityDecision(ctx, domain.VulnerabilityDecision{})},
		{"idempotency", repositories.Idempotency.Insert(ctx, app.IdempotencyRecordKey{}, app.IdempotencyRecord{})},
		{"outbox", repositories.Outbox.Enqueue(ctx, app.OutboxJob{})},
		{"package", repositories.Packages.InsertReleaseBundle(ctx, domain.ReleaseBundle{})},
		{"signing key", repositories.Signatures.InsertSigningKey(ctx, domain.SigningKey{})},
		{"signature", repositories.Signatures.InsertSignature(ctx, domain.Signature{})},
		{"verification", repositories.Verification.InsertVerificationResult(ctx, domain.VerificationResult{})},
	}
	for _, check := range checks {
		if !errors.Is(check.err, app.ErrValidation) {
			t.Errorf("%s err=%v, want validation", check.name, check.err)
		}
	}
	if _, err := repositories.Audit.Append(ctx, domain.AuditChainEntry{}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("invalid audit err=%v, want validation", err)
	}
}

func TestRepositoriesCoverConflictOptionalAndEncodingPaths(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	repositories := postgresrepositories.New(tx)
	now := time.Now().UTC().Round(0)
	tenant := domain.Tenant{ID: "ten_repository_paths", Name: "Paths", CreatedAt: now}
	if err := repositories.Identity.InsertTenant(ctx, tenant); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := repositories.ReleaseCatalog.InsertProduct(ctx, domain.Product{ID: "prod_repository_paths", TenantID: tenant.ID, Name: "Paths API", Slug: "paths-api", CreatedAt: now}); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	evidence := domain.EvidenceItem{ID: "evi_repository_paths", TenantID: tenant.ID, Type: "note", Title: "Optional references", SourceSystem: "test", ObservedAt: now, SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadHash: "sha256:payload", CanonicalHash: "sha256:canonical", Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "untrusted", VerificationStatus: "not_verified", CreatedAt: now}
	if err := repositories.Evidence.InsertEvidence(ctx, evidence); err != nil {
		t.Fatalf("insert evidence with optional references: %v", err)
	}
	badEvidence := evidence
	badEvidence.ID = "evi_repository_bad"
	badEvidence.Metadata = map[string]any{"not_json": math.NaN()}
	if err := repositories.Evidence.InsertEvidence(ctx, badEvidence); err == nil {
		t.Fatal("expected evidence JSON encoding failure")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO vulnerability_scans (id, tenant_id, evidence_id, scanner, target_ref, summary, findings, created_at)
		VALUES ('scan_repository_paths', $1, $2, 'test', 'pkg:oci/paths', '{}'::jsonb, '[]'::jsonb, $3)
	`, tenant.ID, evidence.ID, now); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	if err := repositories.Decisions.InsertVulnerabilityDecision(ctx, domain.VulnerabilityDecision{ID: "dec_repository_paths", TenantID: tenant.ID, FindingID: "finding_paths", ScanID: "scan_repository_paths", Vulnerability: "CVE-2026-0002", Status: "not_affected", Justification: "test", Source: "test", SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert decision with optional references: %v", err)
	}
	for _, id := range []string{"ace_repository_paths_1", "ace_repository_paths_2"} {
		if _, err := repositories.Audit.Append(ctx, domain.AuditChainEntry{ID: id, TenantID: tenant.ID, EntryType: "evidence.created", SubjectType: "evidence_item", SubjectID: evidence.ID, ActorType: "system", ActorID: "test", OccurredAt: now}); err != nil {
			t.Fatalf("append audit %s: %v", id, err)
		}
	}
	job := app.OutboxJob{ID: "job_repository_paths", TenantID: tenant.ID, Kind: "index_evidence", SubjectType: "evidence_item", SubjectID: evidence.ID, CreatedAt: now}
	if err := repositories.Outbox.Enqueue(ctx, job); err != nil {
		t.Fatalf("enqueue outbox job: %v", err)
	}
	key := app.IdempotencyRecordKey{TenantID: tenant.ID, ActorID: "actor_paths", Method: "POST", Path: "/v1/evidence", IdempotencyKey: "idem_paths"}
	record := app.IdempotencyRecord{RequestHash: "sha256:request", Status: 201, Response: map[string]any{"id": evidence.ID}, CreatedAt: now}
	if err := repositories.Idempotency.Insert(ctx, key, record); err != nil {
		t.Fatalf("insert idempotency: %v", err)
	}
	if err := repositories.Idempotency.Insert(ctx, key, record); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("duplicate idempotency err=%v, want conflict", err)
	}
	if err := repositories.Signatures.InsertSigningKey(ctx, domain.SigningKey{ID: "sigkey_repository_paths", TenantID: tenant.ID, KID: "paths-key", Algorithm: "Ed25519", Status: "active", PublicKey: "public", CreatedAt: now}); err != nil {
		t.Fatalf("insert signing key without private bytes: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit path coverage transaction: %v", err)
	}

	conflictTx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin conflict transaction: %v", err)
	}
	defer func() { _ = conflictTx.Rollback(context.Background()) }()
	conflictRepositories := postgresrepositories.New(conflictTx)
	if err := conflictRepositories.ReleaseCatalog.InsertProduct(ctx, domain.Product{ID: "prod_repository_paths", TenantID: tenant.ID, Name: "Paths API", Slug: "paths-api", CreatedAt: now}); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("duplicate product err=%v, want conflict", err)
	}

	closedTx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin closed transaction: %v", err)
	}
	closedRepositories := postgresrepositories.New(closedTx)
	if err := closedTx.Rollback(context.Background()); err != nil {
		t.Fatalf("close transaction: %v", err)
	}
	if err := closedRepositories.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_closed", Name: "Closed", CreatedAt: now}); err == nil {
		t.Fatal("expected closed transaction write failure")
	}
}

func openRepositoryTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "evydence_repositories_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
	})
	scopedURL := repositorySearchPathURL(t, databaseURL, schema)
	store, err := postgres.OpenWithOptions(ctx, scopedURL, postgres.StoreOptions{LoadMode: postgres.LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.ApplyMigrations(ctx, "../../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	pool, err := pgxpool.New(ctx, scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool
}

func repositorySearchPathURL(t *testing.T, rawURL, schema string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
