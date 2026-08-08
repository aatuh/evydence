package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	fsobject "github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
)

func TestPostgresPairedBackupRestoreUsesNativeDumpAndFilesystemGeneration(t *testing.T) {
	baseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	for _, tool := range []string{"pg_dump", "pg_restore", "python3", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required recovery tool %s: %v", tool, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("connect recovery admin database: %v", err)
	}
	defer admin.Close(context.WithoutCancel(ctx))

	suffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "_")
	sourceDB := "evydence_restore_source_" + suffix
	targetDB := "evydence_restore_target_" + suffix
	for _, database := range []string{sourceDB, targetDB} {
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()+" TEMPLATE template0"); err != nil {
			t.Fatalf("create recovery database %s: %v", database, err)
		}
		database := database
		t.Cleanup(func() {
			_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)")
		})
	}

	sourceURL := pairedBackupDatabaseURL(t, baseURL, sourceDB)
	targetURL := pairedBackupDatabaseURL(t, baseURL, targetDB)
	sourceStore, err := OpenWithOptions(ctx, sourceURL, StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sourceStore.Close()
	if _, err := sourceStore.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply source migrations: %v", err)
	}

	sourceObjectRoot := t.TempDir()
	sourceObjects, err := fsobject.New(sourceObjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := app.NewLedgerWithContext(ctx, app.Config{APIKeyPepper: "paired-restore-test-pepper", Store: sourceStore, ObjectStore: sourceObjects})
	if err != nil {
		t.Fatal(err)
	}
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Paired Restore Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Paired Restore API", "paired-restore-api")
	if err != nil {
		t.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "paired.tar.gz", "application/gzip", "sha256:"+strings.Repeat("a", 64), 42)
	if err != nil {
		t.Fatal(err)
	}
	rawSBOM := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:oci/api"}]}`)
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, rawSBOM)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rawSBOM)
	if err := app.FinalizeStagedObjectPayload(ctx, sourceStore, sourceObjects, actor.TenantID, "sha256:"+hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("finalize paired source payload: %v", err)
	}
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, app.CreateRedactionProfileInput{Name: "paired restore", AllowedTypes: []string{"sbom"}, ExcludedFields: []string{"internal_notes"}})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, app.CreateCustomerPackageInput{ProductID: product.ID, ReleaseID: release.ID, RedactionProfileID: profile.ID, Title: "Paired restore package", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Round(0)
	completedAt := now
	uow, err := sourceStore.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	idempotencyKey := app.IdempotencyRecordKey{TenantID: actor.TenantID, ActorID: "key_paired_restore", Method: "POST", Path: "/v1/products", IdempotencyKey: "paired-restore-product"}
	idempotencyRecord := app.IdempotencyRecord{RequestHash: "sha256:" + strings.Repeat("b", 64), Status: 201, Response: map[string]any{"id": product.ID}, CreatedAt: now, UpdatedAt: now, CompletedAt: &completedAt, ExpiresAt: now.Add(24 * time.Hour)}
	if err := uow.Repositories().Idempotency.Insert(ctx, idempotencyKey, idempotencyRecord); err != nil {
		_ = uow.Rollback(ctx)
		t.Fatalf("seed idempotency record: %v", err)
	}
	if err := uow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	pendingJob := app.OutboxJob{ID: "job_paired_restore", TenantID: actor.TenantID, Kind: "index_evidence", SubjectType: "release", SubjectID: release.ID, CreatedAt: now, Payload: map[string]any{"release_id": release.ID}}
	if err := sourceStore.Enqueue(ctx, pendingJob); err != nil {
		t.Fatalf("seed pending outbox job: %v", err)
	}
	checkpoint, err := ledger.GenerateBackupManifest(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}

	backupRoot := t.TempDir()
	databaseDump := filepath.Join(backupRoot, "database.dump")
	backupObjects := filepath.Join(backupRoot, "objects")
	if err := os.MkdirAll(backupObjects, 0o700); err != nil {
		t.Fatal(err)
	}
	copyTree(t, sourceObjectRoot, backupObjects)
	runRecoveryCommand(t, ctx, "pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file", databaseDump, sourceURL)
	releaseCommit := strings.TrimSpace(runRecoveryCommand(t, ctx, "git", "-C", "../../..", "rev-parse", "HEAD"))
	manifestPath := filepath.Join(backupRoot, "paired-backup.json")
	runRecoveryCommand(t, ctx, "python3", "../../../scripts/paired_backup_manifest.py", "create",
		"--database-dump", databaseDump,
		"--objects-dir", backupObjects,
		"--migrations-dir", "../../../migrations",
		"--release-commit", releaseCommit,
		"--checkpoint-id", checkpoint.ID,
		"--checkpoint-state-hash", checkpoint.StateHash,
		"--output", manifestPath,
	)
	runPairedPreflight(t, ctx, manifestPath, databaseDump, backupObjects, releaseCommit, false)

	mismatchedDump := copyRecoveryFileToTemp(t, databaseDump)
	file, err := os.OpenFile(mismatchedDump, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("database-newer"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	_ = file.Close()
	runPairedPreflight(t, ctx, manifestPath, mismatchedDump, backupObjects, releaseCommit, true)

	mismatchedObjects := t.TempDir()
	copyTree(t, backupObjects, mismatchedObjects)
	if err := os.WriteFile(filepath.Join(mismatchedObjects, "objects-newer"), []byte("new-generation"), 0o600); err != nil {
		t.Fatal(err)
	}
	runPairedPreflight(t, ctx, manifestPath, databaseDump, mismatchedObjects, releaseCommit, true)

	// The paired generation is verified before any restored application process is opened.
	runPairedPreflight(t, ctx, manifestPath, databaseDump, backupObjects, releaseCommit, false)
	runRecoveryCommand(t, ctx, "pg_restore", "--no-owner", "--no-privileges", "--dbname", targetURL, databaseDump)
	targetObjectRoot := t.TempDir()
	copyTree(t, backupObjects, targetObjectRoot)
	targetObjects, err := fsobject.New(targetObjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	targetStore, err := OpenWithOptions(ctx, targetURL, StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer targetStore.Close()
	if err := targetStore.RequireNoPendingMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("restored database migration identity: %v", err)
	}
	restored, err := app.NewLedgerWithContext(ctx, app.Config{APIKeyPepper: "paired-restore-test-pepper", Store: targetStore, ObjectStore: targetObjects})
	if err != nil {
		t.Fatal(err)
	}
	restoredActor, err := restored.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := restored.VerifyBackupManifest(ctx, restoredActor, checkpoint.ID); err != nil {
		t.Fatalf("verify restored consistency checkpoint: %v result=%#v", err, result)
	}
	if result, err := restored.VerifySubject(ctx, restoredActor, "audit_chain", ""); err != nil || result.Result != "passed" {
		t.Fatalf("verify restored audit chain: result=%#v err=%v", result, err)
	}
	if result, err := restored.VerifySubject(ctx, restoredActor, "release_bundle", bundle.ID); err != nil || result.Result != "passed" {
		t.Fatalf("verify restored release bundle: result=%#v err=%v", result, err)
	}
	restoredSBOM, err := restored.GetSBOM(ctx, restoredActor, sbom.ID)
	if err != nil || restoredSBOM.ComponentCount != sbom.ComponentCount {
		t.Fatalf("restored SBOM=%#v err=%v", restoredSBOM, err)
	}
	evidence, err := restored.GetEvidence(ctx, restoredActor, restoredSBOM.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	object, err := targetObjects.Get(ctx, strings.TrimPrefix(evidence.PayloadRef, "object://"))
	if err != nil || object.Digest != evidence.PayloadHash {
		t.Fatalf("restored object digest=%q want=%q err=%v", object.Digest, evidence.PayloadHash, err)
	}
	var restoredPackageHash string
	if err := targetStore.pool.QueryRow(ctx, `SELECT manifest_hash FROM customer_security_packages WHERE tenant_id=$1 AND id=$2`, actor.TenantID, pkg.ID).Scan(&restoredPackageHash); err != nil {
		t.Fatal(err)
	}
	if restoredPackageHash != pkg.ManifestHash {
		t.Fatalf("restored package manifest hash=%q want=%q", restoredPackageHash, pkg.ManifestHash)
	}
	packageAfter, err := restored.ExportCustomerSecurityPackageArchive(ctx, restoredActor, pkg.ID)
	if err != nil || packageAfter.PackageID != pkg.ID || packageAfter.Hash == "" || packageAfter.Size != int64(len(packageAfter.Bytes)) {
		t.Fatalf("restored customer package archive=%#v err=%v", packageAfter, err)
	}
	var idempotencyState string
	var idempotencyStatus int
	if err := targetStore.pool.QueryRow(ctx, `SELECT state, status FROM idempotency_records WHERE tenant_id=$1 AND idempotency_key=$2`, actor.TenantID, idempotencyKey.IdempotencyKey).Scan(&idempotencyState, &idempotencyStatus); err != nil {
		t.Fatal(err)
	}
	if idempotencyState != string(app.IdempotencyCompleted) || idempotencyStatus != 201 {
		t.Fatalf("restored idempotency state/status=%s/%d", idempotencyState, idempotencyStatus)
	}
	var outboxStatus string
	if err := targetStore.pool.QueryRow(ctx, `SELECT status FROM outbox_jobs WHERE id=$1`, pendingJob.ID).Scan(&outboxStatus); err != nil {
		t.Fatal(err)
	}
	if outboxStatus != "queued" {
		t.Fatalf("restored pending job status=%q, want queued", outboxStatus)
	}
}

func pairedBackupDatabaseURL(t *testing.T, rawURL, database string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + database
	return parsed.String()
}

func runRecoveryCommand(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	var command *exec.Cmd
	switch name {
	case "pg_dump":
		// #nosec G702 -- fixed test-only executable; args are generated backup paths and the configured test database URL.
		command = exec.CommandContext(ctx, "pg_dump", args...)
	case "pg_restore":
		// #nosec G702 -- fixed test-only executable; args are generated backup paths and the configured test database URL.
		command = exec.CommandContext(ctx, "pg_restore", args...)
	case "python3":
		// #nosec G702 -- fixed repository-owned script runner with generated local backup arguments.
		command = exec.CommandContext(ctx, "python3", args...)
	case "git":
		// #nosec G702 -- fixed test-only executable used for repository HEAD identity.
		command = exec.CommandContext(ctx, "git", args...)
	default:
		t.Fatalf("unsupported recovery command %q", name)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}

func runPairedPreflight(t *testing.T, ctx context.Context, manifestPath, databaseDump, objectsDir, releaseCommit string, wantFailure bool) {
	t.Helper()
	// #nosec G204 -- test-only execution of repository-owned recovery preflight.
	command := exec.CommandContext(ctx, "python3", "../../../scripts/paired_backup_manifest.py", "verify",
		"--manifest", manifestPath,
		"--database-dump", databaseDump,
		"--objects-dir", objectsDir,
		"--migrations-dir", "../../../migrations",
		"--release-commit", releaseCommit,
	)
	output, err := command.CombinedOutput()
	if wantFailure {
		if err == nil || !strings.Contains(string(output), "safe decision: do not start Evydence") {
			t.Fatalf("mismatched generation preflight err=%v output=%s", err, output)
		}
		return
	}
	if err != nil {
		t.Fatalf("paired generation preflight: %v\n%s", err, output)
	}
}

func copyRecoveryFileToTemp(t *testing.T, source string) string {
	t.Helper()
	body, err := os.ReadFile(source) // #nosec G304 -- test-owned temporary backup path.
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "database-*.dump")
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return name
}
