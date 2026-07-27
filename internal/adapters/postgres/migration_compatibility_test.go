package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
)

func TestMigrationCompatibilityFromEveryCommittedState(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if strings.TrimSpace(databaseURL) == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	names := migrationFileNames(t, "../../../migrations")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	basePool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer basePool.Close()

	for prefix := 0; prefix <= len(names); prefix++ {
		prefix := prefix
		t.Run(fmt.Sprintf("prefix_%02d", prefix), func(t *testing.T) {
			schema := fmt.Sprintf("evydence_migration_%d_%02d", time.Now().UnixNano(), prefix)
			quotedSchema := pgx.Identifier{schema}.Sanitize()
			if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
				t.Fatal(err)
			}
			defer func(cleanupCtx context.Context) {
				_, _ = basePool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
			}(context.WithoutCancel(ctx))

			store, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, schema))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			applyMigrationPrefix(t, ctx, store, "../../../migrations", names[:prefix])
			applied, err := store.ApplyMigrations(ctx, "../../../migrations")
			if err != nil {
				t.Fatalf("upgrade from prefix %d: %v", prefix, err)
			}
			if want := len(names) - prefix; applied != want {
				t.Fatalf("applied migrations = %d, want %d", applied, want)
			}
			var count int
			if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != len(names) {
				t.Fatalf("schema_migrations count = %d, want %d", count, len(names))
			}
			again, err := store.ApplyMigrations(ctx, "../../../migrations")
			if err != nil {
				t.Fatalf("idempotent apply from prefix %d: %v", prefix, err)
			}
			if again != 0 {
				t.Fatalf("second apply = %d, want 0", again)
			}
			for _, table := range []string{"ledger_state", "resource_index", "outbox_jobs", "schema_migrations"} {
				var exists bool
				err := store.pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists)
				if err != nil {
					t.Fatal(err)
				}
				if !exists {
					t.Fatalf("table %s is missing after migration upgrade", table)
				}
			}
		})
	}
}

func TestSequenceAndRevisionMigrationPreservesExistingRecords(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if strings.TrimSpace(databaseURL) == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	const migration = "20260727000400_audit_sequences_and_resource_revisions.up.sql"
	names := migrationFileNames(t, "../../../migrations")
	index := -1
	for i, name := range names {
		if name == migration {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatalf("migration %q not found", migration)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	basePool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer basePool.Close()
	schema := fmt.Sprintf("evydence_sequence_revision_legacy_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = basePool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, schema))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applyMigrationPrefix(t, ctx, store, "../../../migrations", names[:index])
	now := time.Now().UTC().Round(0)
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ('ten_legacy_revision', 'Legacy revisions', $1)`, now); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ('prod_legacy_revision', 'ten_legacy_revision', 'Legacy product', 'legacy-product', $1)`, now); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ('rel_legacy_revision', 'ten_legacy_revision', 'prod_legacy_revision', '1.0.0', 'draft', $1)`, now); err != nil {
		t.Fatalf("insert release: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO release_candidates (id, tenant_id, release_id, name, state, snapshot_hash, document, schema_version, created_at) VALUES ('rc_legacy_revision', 'ten_legacy_revision', 'rel_legacy_revision', 'legacy', 'open', 'sha256:legacy', '{}'::jsonb, 'release-candidate.v1.0.0', $1)`, now); err != nil {
		t.Fatalf("insert release candidate: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO audit_chain_entries (
			id, tenant_id, sequence, entry_type, subject_type, subject_id,
			actor_type, actor_id, occurred_at, request_id, idempotency_key,
			canonical_entry_hash, previous_entry_hash, entry_hash, metadata, schema_version
		) VALUES ('ace_legacy_revision', 'ten_legacy_revision', 7, 'legacy', 'release', 'rel_legacy_revision', 'system', 'migration-test', $1, '', '', 'canonical', 'previous', 'entry', '{}'::jsonb, 'audit-chain-entry.v1.0.0')
	`, now); err != nil {
		t.Fatalf("insert audit entry: %v", err)
	}
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply sequence and revision migration: %v", err)
	}
	var releaseRevision, candidateRevision, nextSequence int64
	if err := store.pool.QueryRow(ctx, `SELECT revision FROM releases WHERE id = 'rel_legacy_revision'`).Scan(&releaseRevision); err != nil {
		t.Fatalf("load release revision: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT revision FROM release_candidates WHERE id = 'rc_legacy_revision'`).Scan(&candidateRevision); err != nil {
		t.Fatalf("load candidate revision: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT next_sequence FROM tenant_audit_sequences WHERE tenant_id = 'ten_legacy_revision'`).Scan(&nextSequence); err != nil {
		t.Fatalf("load audit sequence: %v", err)
	}
	if releaseRevision != 1 || candidateRevision != 1 || nextSequence != 8 {
		t.Fatalf("legacy migration revisions=%d/%d next_sequence=%d, want 1/1/8", releaseRevision, candidateRevision, nextSequence)
	}
}

func TestIdempotencyStateMachineMigratesLegacyReplayRecords(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if strings.TrimSpace(databaseURL) == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	const stateMachineMigration = "20260726000200_idempotency_state_machine.up.sql"
	names := migrationFileNames(t, "../../../migrations")
	stateMachineIndex := -1
	for i, name := range names {
		if name == stateMachineMigration {
			stateMachineIndex = i
			break
		}
	}
	if stateMachineIndex < 0 {
		t.Fatalf("migration %q not found", stateMachineMigration)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	basePool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer basePool.Close()
	schema := fmt.Sprintf("evydence_idempotency_legacy_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = basePool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))
	store, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, schema))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applyMigrationPrefix(t, ctx, store, "../../../migrations", names[:stateMachineIndex])
	now := time.Now().UTC().Round(0)
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ('ten_legacy_idempotency', 'Legacy idempotency', $1)`, now); err != nil {
		t.Fatalf("insert legacy tenant: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO api_keys (id, tenant_id, name, prefix, hash, scopes, created_at) VALUES ('key_legacy_idempotency', 'ten_legacy_idempotency', 'Legacy key', 'legacy', 'hash', '[]'::jsonb, $1)`, now); err != nil {
		t.Fatalf("insert legacy API key: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO idempotency_records (
			tenant_id, actor_key_id, method, path, idempotency_key, request_hash, status, response, created_at
		) VALUES ('ten_legacy_idempotency', 'key_legacy_idempotency', 'POST', '/v1/products', 'legacy-key', 'sha256:legacy-request', 201, '{"id":"prod_legacy","secret":"legacy-one-time-secret"}'::jsonb, $1)
	`, now); err != nil {
		t.Fatalf("insert legacy idempotency record: %v", err)
	}
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply state machine migration: %v", err)
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin replay transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	reservation := app.IdempotencyReservation{
		Key:            app.IdempotencyRecordKey{TenantID: "ten_legacy_idempotency", ActorID: "api_key:key_legacy_idempotency", Method: "POST", Path: "/v1/products", IdempotencyKey: "legacy-key"},
		RequestHash:    "sha256:legacy-request",
		OwnerTokenHash: "sha256:new-owner",
		Now:            now.Add(time.Hour),
		LeaseExpiresAt: now.Add(2 * time.Hour),
		ExpiresAt:      now.Add(25 * time.Hour),
	}
	result, err := postgresrepositories.New(tx).Idempotency.Reserve(ctx, reservation)
	if err != nil || result.Outcome != app.IdempotencyReservationReplay || result.Record.Status != 201 {
		t.Fatalf("legacy replay result=%#v err=%v, want completed replay", result, err)
	}
	response, ok := result.Record.Response.(map[string]any)
	if !ok || response["id"] != "prod_legacy" || response["secret"] != nil {
		t.Fatalf("legacy replay response=%#v, want redacted resource response", result.Record.Response)
	}
	if result.Record.State != app.IdempotencyCompleted || result.Record.CompletedAt == nil || result.Record.ExpiresAt.Before(now.Add(23*time.Hour)) {
		t.Fatalf("legacy record was not upgraded with completed retention metadata: %#v", result.Record)
	}
}

func TestVerificationAssuranceTaxonomyMigratesLegacyResultsConservatively(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if strings.TrimSpace(databaseURL) == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	const taxonomyMigration = "20260722000100_verification_assurance_taxonomy.up.sql"
	names := migrationFileNames(t, "../../../migrations")
	taxonomyIndex := -1
	for i, name := range names {
		if name == taxonomyMigration {
			taxonomyIndex = i
			break
		}
	}
	if taxonomyIndex < 0 {
		t.Fatalf("migration %q not found", taxonomyMigration)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	basePool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer basePool.Close()

	schema := fmt.Sprintf("evydence_assurance_taxonomy_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = basePool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, schema))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applyMigrationPrefix(t, ctx, store, "../../../migrations", names[:taxonomyIndex])

	now := time.Now().UTC()
	if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, $3)`, "legacy-tenant", "Legacy tenant", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO verification_results (id, tenant_id, subject_type, subject_id, result, checks, verified_at)
		VALUES
			('legacy-generic-passed', 'legacy-tenant', 'release_bundle', 'bundle-1', 'passed', '[]'::jsonb, $1),
			('legacy-generic-failed', 'legacy-tenant', 'release_bundle', 'bundle-2', 'failed', '[]'::jsonb, $1)
	`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO cosign_verifications (
			id, tenant_id, artifact_signature_id, subject_digest, result, checks, schema_version, created_at
		) VALUES ('legacy-cosign-passed', 'legacy-tenant', 'signature-1', 'sha256:legacy', 'passed', '[]'::jsonb, 'cosign-verification.v1.0.0', $1)
	`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO provider_verifications (
			id, tenant_id, provider_type, provider_id, subject, result, checks, limitations, schema_version, created_at
		) VALUES ('legacy-provider-passed', 'legacy-tenant', 'oidc', 'provider-1', 'subject-1', 'passed', '[]'::jsonb, '{}', 'provider-verification.v1.0.0', $1)
	`, now); err != nil {
		t.Fatal(err)
	}

	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	assertLegacyVerificationResult(t, ctx, store.pool, "legacy-generic-passed", "limited", "legacy-ambiguous-verification.v1", "verification-result.v2.0.0")
	assertLegacyVerificationResult(t, ctx, store.pool, "legacy-generic-failed", "failed", "legacy-ambiguous-verification.v1", "verification-result.v2.0.0")
	assertLegacyReceipt(t, ctx, store.pool, "cosign_verifications", "legacy-cosign-passed", "limited", "legacy-cosign-metadata.v1", "cosign-verification.v2.0.0")
	assertLegacyReceipt(t, ctx, store.pool, "provider_verifications", "legacy-provider-passed", "limited", "legacy-provider-verification.v1", "provider-verification.v2.0.0")
}

func TestObjectRetentionVerificationTruthMigratesLegacyRecordsConservatively(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if strings.TrimSpace(databaseURL) == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	const retentionMigration = "20260722000200_object_retention_verification_truth.up.sql"
	names := migrationFileNames(t, "../../../migrations")
	retentionIndex := -1
	for i, name := range names {
		if name == retentionMigration {
			retentionIndex = i
			break
		}
	}
	if retentionIndex < 0 {
		t.Fatalf("migration %q not found", retentionMigration)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	basePool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer basePool.Close()

	schema := fmt.Sprintf("evydence_retention_truth_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = basePool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, schema))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applyMigrationPrefix(t, ctx, store, "../../../migrations", names[:retentionIndex])

	now := time.Now().UTC()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO object_retention_policies (
			id, tenant_id, name, object_prefix, object_key, require_legal_hold, mode,
			retention_days, status, verified_at, verification_hash, verification_checks,
			verification_limitations, schema_version, created_at
		) VALUES (
			'legacy-retention', 'legacy-tenant', 'Legacy retention', 'tenants/legacy-tenant/',
			'', false, 'compliance', 90, 'verified', $1, 'legacy-hash', '[]'::jsonb,
			'{}', 'object-retention-policy.v1.0.0', $1
		)
	`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}

	var status, provider, bucket, schemaVersion string
	var maxAge, retentionDays int
	var observedAt, expiresAt sql.NullTime
	var limitations []string
	if err := store.pool.QueryRow(ctx, `
		SELECT status, max_verification_age_hours, verification_provider, verification_bucket,
			verification_retention_days, verification_observed_at, verification_expires_at,
			verification_limitations, schema_version
		FROM object_retention_policies WHERE id = 'legacy-retention'
	`).Scan(&status, &maxAge, &provider, &bucket, &retentionDays, &observedAt, &expiresAt, &limitations, &schemaVersion); err != nil {
		t.Fatal(err)
	}
	if status != "not_verified" || maxAge != 24 || provider != "" || bucket != "" || retentionDays != 0 || observedAt.Valid || expiresAt.Valid || schemaVersion != "object-retention-policy.v2.0.0" || len(limitations) == 0 {
		t.Fatalf("legacy retention migration = status:%q max_age:%d provider:%q bucket:%q retention_days:%d observed_at:%v expires_at:%v limitations:%#v schema:%q", status, maxAge, provider, bucket, retentionDays, observedAt, expiresAt, limitations, schemaVersion)
	}
}

func TestOutboxDeadLetterMigrationSanitizesLegacyFailures(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if strings.TrimSpace(databaseURL) == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	const migration = "20260727000500_outbox_dead_letter_controls.up.sql"
	names := migrationFileNames(t, "../../../migrations")
	index := -1
	for i, name := range names {
		if name == migration {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatalf("migration %q not found", migration)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	basePool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer basePool.Close()
	schema := fmt.Sprintf("evydence_outbox_legacy_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = basePool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := Open(ctx, databaseURLWithSearchPath(t, databaseURL, schema))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	applyMigrationPrefix(t, ctx, store, "../../../migrations", names[:index])
	now := time.Now().UTC().Round(0)
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO outbox_jobs (id, tenant_id, kind, subject_type, subject_id, status, attempts, max_attempts, last_error, created_at, updated_at)
		VALUES
			('job_legacy_failed', 'ten_legacy_outbox', 'parse_sbom', 'sbom', 'sbom_legacy_failed', 'failed', 5, 5, 'postgres://user:secret@example.test/db', $1, $1),
			('job_legacy_retrying', 'ten_legacy_outbox', 'parse_sbom', 'sbom', 'sbom_legacy_retrying', 'retrying', 1, 5, 'object store read token=secret', $1, $1)
	`, now); err != nil {
		t.Fatalf("insert legacy outbox jobs: %v", err)
	}
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply outbox lifecycle migration: %v", err)
	}

	for _, check := range []struct {
		id, status, failureClass, failureCode, dedupe string
		terminal                                      bool
	}{
		{"job_legacy_failed", "dead_letter", "permanent", "legacy_failed", "legacy:job_legacy_failed", true},
		{"job_legacy_retrying", "retrying", "transient", "legacy_retry_failed", "legacy:job_legacy_retrying", false},
	} {
		var status, failureClass, failureCode, lastError, dedupe string
		var terminalAt sql.NullTime
		if err := store.pool.QueryRow(ctx, `
			SELECT status, failure_class, failure_code, last_error, deduplication_key, terminal_at
			FROM outbox_jobs WHERE id = $1
		`, check.id).Scan(&status, &failureClass, &failureCode, &lastError, &dedupe, &terminalAt); err != nil {
			t.Fatalf("load migrated outbox job %s: %v", check.id, err)
		}
		if status != check.status || failureClass != check.failureClass || failureCode != check.failureCode || lastError != check.failureCode || dedupe != check.dedupe || terminalAt.Valid != check.terminal {
			t.Fatalf("migrated outbox job %s = status:%q class:%q code:%q last_error:%q dedupe:%q terminal:%v", check.id, status, failureClass, failureCode, lastError, dedupe, terminalAt.Valid)
		}
	}
}

func assertLegacyVerificationResult(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id, wantResult, wantProfile, wantVersion string) {
	t.Helper()
	var result, profileID, schemaVersion string
	var limitations []string
	if err := pool.QueryRow(ctx, `SELECT result, assurance_profile->>'id', limitations, schema_version FROM verification_results WHERE id = $1`, id).Scan(&result, &profileID, &limitations, &schemaVersion); err != nil {
		t.Fatal(err)
	}
	if result != wantResult || profileID != wantProfile || schemaVersion != wantVersion || len(limitations) == 0 {
		t.Fatalf("legacy verification %s = result:%q profile:%q limitations:%#v version:%q", id, result, profileID, limitations, schemaVersion)
	}
}

func assertLegacyReceipt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, id, wantResult, wantProfile, wantVersion string) {
	t.Helper()
	var result, profileID, schemaVersion string
	var limitations []string
	query := fmt.Sprintf("SELECT result, assurance_profile->>'id', limitations, schema_version FROM %s WHERE id = $1", pgx.Identifier{table}.Sanitize())
	if err := pool.QueryRow(ctx, query, id).Scan(&result, &profileID, &limitations, &schemaVersion); err != nil {
		t.Fatal(err)
	}
	if result != wantResult || profileID != wantProfile || schemaVersion != wantVersion || len(limitations) == 0 {
		t.Fatalf("legacy receipt %s/%s = result:%q profile:%q limitations:%#v version:%q", table, id, result, profileID, limitations, schemaVersion)
	}
}

func migrationFileNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no migration files found")
	}
	return names
}

func applyMigrationPrefix(t *testing.T, ctx context.Context, store *Store, dir string, names []string) {
	t.Helper()
	if _, err := store.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		version := strings.TrimSuffix(name, ".up.sql")
		body, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- migration names come from ReadDir and are filtered to .up.sql files.
		if err != nil {
			t.Fatal(err)
		}
		tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("apply prefix migration %s: %v", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("record prefix migration %s: %v", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func databaseURLWithSearchPath(t *testing.T, rawURL, schema string) string {
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
