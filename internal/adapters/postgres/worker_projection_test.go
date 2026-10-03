package postgres

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestStoreLoadWorkerProjectionRejectsInvalidBoundary(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		store    *Store
		ctx      context.Context
		tenantID string
		wantErr  error
	}{
		{name: "nil store", ctx: context.Background(), tenantID: "ten_1", wantErr: app.ErrValidation},
		{name: "nil pool", store: &Store{}, ctx: context.Background(), tenantID: "ten_1", wantErr: app.ErrValidation},
		{name: "nil context", store: &Store{}, tenantID: "ten_1", wantErr: app.ErrValidation},
		{name: "blank tenant", store: &Store{}, ctx: context.Background(), tenantID: " \t", wantErr: app.ErrValidation},
	} {
		t.Run(test.name, func(t *testing.T) {
			projection, err := test.store.LoadWorkerProjection(test.ctx, test.tenantID)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("LoadWorkerProjection error = %v, want %v", err, test.wantErr)
			}
			if !reflect.DeepEqual(projection, app.WorkerProjection{}) {
				t.Fatalf("LoadWorkerProjection returned partial projection: %#v", projection)
			}
		})
	}
}

func TestUnitOfWorkWorkerProjectionUsesActiveConnection(t *testing.T) {
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
	schema := "evydence_uow_projection_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = admin.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	scopedURL := databaseURLWithSearchPath(t, databaseURL, schema) + "&pool_max_conns=1"
	store, err := OpenWithOptions(ctx, scopedURL, StoreOptions{
		LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	now := time.Now().UTC().Round(time.Microsecond)
	if err := store.ApplyCriticalMutation(ctx, app.CriticalMutation{Tenants: []domain.Tenant{{
		ID: "ten_uow_projection", Name: "UOW projection", CreatedAt: now,
	}}}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, workerProjectionMutation("ten_uow_projection", "u", now)); err != nil {
		t.Fatalf("seed projection: %v", err)
	}

	uow, err := store.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatalf("BeginUnitOfWork: %v", err)
	}
	defer func() { _ = uow.Rollback(context.Background()) }()
	projectionStore := uow.Repositories().WorkerProjection
	if projectionStore == nil {
		t.Fatal("unit of work has no worker projection repository")
	}
	loadCtx, loadCancel := context.WithTimeout(ctx, 3*time.Second)
	defer loadCancel()
	projection, err := projectionStore.LoadWorkerProjection(loadCtx, "ten_uow_projection")
	if err != nil {
		t.Fatalf("load transaction projection: %v", err)
	}
	assertWorkerProjection(t, projection, "ten_uow_projection", "u")
}

func TestTransactionWorkerProjectionBlocksConcurrentMutationUntilCommit(t *testing.T) {
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
	schema := "evydence_projection_lock_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	tenantID := "ten_" + schema
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = admin.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	scopedURL := databaseURLWithSearchPath(t, databaseURL, schema)
	reader, err := OpenWithOptions(ctx, scopedURL, StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	writer, err := OpenWithOptions(ctx, scopedURL, StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	now := time.Now().UTC().Round(time.Microsecond)
	if err := writer.ApplyCriticalMutation(ctx, app.CriticalMutation{Tenants: []domain.Tenant{{
		ID: tenantID, Name: "Projection lock", CreatedAt: now,
	}}}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := writer.ApplyReleaseLedgerMutation(ctx, workerProjectionMutation(tenantID, "l", now)); err != nil {
		t.Fatalf("seed projection: %v", err)
	}

	uow, err := reader.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatalf("BeginUnitOfWork: %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = uow.Rollback(context.Background())
		}
	}()
	projection, err := uow.Repositories().WorkerProjection.LoadWorkerProjection(ctx, tenantID)
	if err != nil {
		t.Fatalf("load transaction projection: %v", err)
	}
	mutation := app.ReleaseLedgerMutation{Scans: []domain.VulnerabilityScan{projection.Scans[0]}}
	mutation.Scans[0].Summary = map[string]int{"high": 2}

	blockedCtx, blockedCancel := context.WithTimeout(ctx, 250*time.Millisecond)
	err = writer.ApplyReleaseLedgerMutation(blockedCtx, mutation)
	blockedCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent mutation error = %v, want shared projection lock timeout", err)
	}
	auditUOW, err := writer.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatalf("begin concurrent audit unit of work: %v", err)
	}
	defer func() { _ = auditUOW.Rollback(context.Background()) }()
	auditCtx, auditCancel := context.WithTimeout(ctx, 250*time.Millisecond)
	_, err = auditUOW.Repositories().Audit.Append(auditCtx, domain.AuditChainEntry{
		ID: "ace_projection_lock_concurrent", TenantID: tenantID,
		EntryType: "projection.concurrent", SubjectType: "projection", SubjectID: "projection_lock",
		ActorType: "worker", ActorID: "projection-test", OccurredAt: now.Add(time.Second),
	})
	auditCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent audit error = %v, want projection lock timeout", err)
	}
	// The canceled lock wait may make pgx discard the connection before the
	// explicit cleanup call. The command error above is the tested outcome.
	_ = auditUOW.Rollback(context.Background())
	if err := uow.Commit(ctx); err != nil {
		t.Fatalf("commit projection reader: %v", err)
	}
	closed = true
	if err := writer.ApplyReleaseLedgerMutation(ctx, mutation); err != nil {
		t.Fatalf("mutation after projection commit: %v", err)
	}
	updated, err := writer.LoadWorkerProjection(ctx, tenantID)
	if err != nil {
		t.Fatalf("load updated projection: %v", err)
	}
	if got := updated.Scans[0].Summary["high"]; got != 2 {
		t.Fatalf("updated high summary = %d, want 2", got)
	}
}

func TestStoreLoadWorkerProjectionIsTenantIsolated(t *testing.T) {
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
	schema := "evydence_worker_projection_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = admin.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{
		LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Now().UTC().Round(time.Microsecond)
	for _, tenant := range []domain.Tenant{
		{ID: "ten_projection_a", Name: "Projection A", CreatedAt: now},
		{ID: "ten_projection_b", Name: "Projection B", CreatedAt: now.Add(time.Second)},
	} {
		if err := store.ApplyCriticalMutation(ctx, app.CriticalMutation{Tenants: []domain.Tenant{tenant}}); err != nil {
			t.Fatalf("seed tenant %s: %v", tenant.ID, err)
		}
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, workerProjectionMutation("ten_projection_a", "a", now)); err != nil {
		t.Fatalf("seed tenant A projection: %v", err)
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, workerProjectionMutation("ten_projection_b", "b", now.Add(time.Second))); err != nil {
		t.Fatalf("seed tenant B projection: %v", err)
	}

	projectionA, err := store.LoadWorkerProjection(ctx, "ten_projection_a")
	if err != nil {
		t.Fatalf("load tenant A projection: %v", err)
	}
	assertWorkerProjection(t, projectionA, "ten_projection_a", "a")

	projectionB, err := store.LoadWorkerProjection(ctx, "ten_projection_b")
	if err != nil {
		t.Fatalf("load tenant B projection: %v", err)
	}
	assertWorkerProjection(t, projectionB, "ten_projection_b", "b")

	empty, err := store.LoadWorkerProjection(ctx, "ten_projection_missing")
	if err != nil {
		t.Fatalf("load missing tenant projection: %v", err)
	}
	if !reflect.DeepEqual(empty, app.WorkerProjection{}) {
		t.Fatalf("missing tenant projection = %#v, want empty", empty)
	}
}

func workerProjectionMutation(tenantID, suffix string, now time.Time) app.ReleaseLedgerMutation {
	digest := "sha256:" + strings.Repeat(suffix, 64)
	evidenceID := "ev_projection_" + suffix
	sbomID := "sbom_projection_" + suffix
	scanID := "scan_projection_" + suffix
	vexID := "vex_projection_" + suffix
	return app.ReleaseLedgerMutation{
		Evidence: []domain.EvidenceItem{{
			ID: evidenceID, TenantID: tenantID, Type: "sbom", Title: "Projection " + suffix,
			SourceSystem: "test", ObservedAt: now, EvidenceVersion: 1,
			SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadHash: digest, CanonicalHash: digest,
			Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "L2",
			VerificationStatus: "verified", CreatedAt: now,
		}},
		SBOMs: []domain.SBOM{{
			ID: sbomID, TenantID: tenantID, EvidenceID: evidenceID, ReleaseID: "rel_projection_" + suffix,
			ArtifactID: "art_projection_" + suffix, Format: "cyclonedx", SpecVersion: "1.6",
			ComponentCount: 1, Components: []domain.SBOMComponent{{Name: "component-" + suffix, Version: "1.0.0"}}, CreatedAt: now,
		}},
		Scans: []domain.VulnerabilityScan{{
			ID: scanID, TenantID: tenantID, EvidenceID: evidenceID, ReleaseID: "rel_projection_" + suffix,
			Scanner: "scanner-" + suffix, Adapter: "generic", AdapterVersion: "generic.v1", SourceSchema: "generic.v1",
			TargetRef: "target-" + suffix, Summary: map[string]int{"high": 1},
			Findings:  []domain.VulnerabilityFinding{{ID: "finding_projection_" + suffix, Vulnerability: "CVE-2099-000" + suffix, Severity: "high", State: "open"}},
			CreatedAt: now,
		}},
		Contracts: []domain.OpenAPIContract{{
			ID: "contract_projection_" + suffix, TenantID: tenantID, ProductID: "prod_projection_" + suffix,
			ReleaseID: "rel_projection_" + suffix, Version: "1.0.0", Hash: digest, PathCount: 1,
			Operations: []domain.OpenAPIOperation{{Path: "/" + suffix, Method: "GET", OperationID: "get" + suffix}},
			EvidenceID: evidenceID, CreatedAt: now,
		}},
		VEXDocuments: []domain.VEXDocument{{
			ID: vexID, TenantID: tenantID, EvidenceID: evidenceID, ReleaseID: "rel_projection_" + suffix,
			ArtifactID: "art_projection_" + suffix, Format: "openvex", Author: "security-" + suffix,
			Version: "1", StatementCount: 1, StatusSummary: map[string]int{"not_affected": 1},
			SchemaVersion: domain.VEXDocumentSchemaVersion, CreatedAt: now,
		}},
		VEXImportReports: []domain.VEXImportReport{{
			ID: "report_projection_" + suffix, TenantID: tenantID, VEXDocumentID: vexID,
			EvidenceID: evidenceID, ReleaseID: "rel_projection_" + suffix, ArtifactID: "art_projection_" + suffix,
			ParserVersion: app.ParserVersionOpenVEXJSON, Status: "parsed", StatementCount: 1,
			DecisionsCreated: 1, UnsupportedFields: []string{"extension-" + suffix},
			Warnings: []string{"warning-" + suffix}, SchemaVersion: domain.VEXImportReportSchemaVersion,
			CreatedAt: now, UpdatedAt: now,
		}},
		BuildAttestations: []domain.BuildAttestation{{
			ID: "attestation_projection_" + suffix, TenantID: tenantID, BuildID: "build_projection_" + suffix,
			EvidenceID: evidenceID, PayloadHash: digest, PayloadSize: 42, PayloadType: "application/json",
			PredicateType: "https://slsa.dev/provenance/v1", SubjectDigests: []string{digest},
			BuilderID: "builder-" + suffix, BuildType: "test", MaterialsCount: 1, SignatureCount: 1,
			VerificationStatus: "structurally_valid", SchemaVersion: domain.BuildAttestationSchemaVersion, CreatedAt: now,
		}},
		VulnerabilityDecisions: []domain.VulnerabilityDecision{{
			ID: "decision_projection_" + suffix, TenantID: tenantID, FindingID: "finding_projection_" + suffix,
			ScanID: scanID, ReleaseID: "rel_projection_" + suffix, Vulnerability: "CVE-2099-000" + suffix,
			Component: "component-" + suffix, SBOMID: sbomID, SBOMComponentName: "component-" + suffix,
			Status: "not_affected", Justification: "component_not_present", Source: "vex", EvidenceID: evidenceID,
			EvidenceIDs: []string{evidenceID}, SupportingRefs: []domain.SubjectRef{{Type: "artifact", ID: "art_projection_" + suffix}},
			VEXDocumentID: vexID, SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: now,
		}},
		AuditChainEntries: []domain.AuditChainEntry{{
			ID: "chain_projection_" + suffix, TenantID: tenantID, EntryType: "worker.projection",
			SubjectType: "evidence_item", SubjectID: evidenceID, ActorType: "worker", ActorID: "worker-" + suffix,
			OccurredAt: now, PayloadHash: digest, Metadata: map[string]any{"suffix": suffix},
			SchemaVersion: domain.AuditChainEntrySchemaVersion,
		}},
	}
}

func assertWorkerProjection(t *testing.T, projection app.WorkerProjection, tenantID, suffix string) {
	t.Helper()
	for name, count := range map[string]int{
		"SBOMs":                  len(projection.SBOMs),
		"Scans":                  len(projection.Scans),
		"Contracts":              len(projection.Contracts),
		"VEXDocuments":           len(projection.VEXDocuments),
		"VEXImportReports":       len(projection.VEXImportReports),
		"BuildAttestations":      len(projection.BuildAttestations),
		"VulnerabilityDecisions": len(projection.VulnerabilityDecisions),
		"AuditChainEntries":      len(projection.AuditChainEntries),
	} {
		if count != 1 {
			t.Fatalf("%s count = %d, want 1", name, count)
		}
	}
	assertProjectionRecord(t, "SBOMs", projection.SBOMs[0].ID, projection.SBOMs[0].TenantID, "sbom_projection_"+suffix, tenantID)
	assertProjectionRecord(t, "Scans", projection.Scans[0].ID, projection.Scans[0].TenantID, "scan_projection_"+suffix, tenantID)
	assertProjectionRecord(t, "Contracts", projection.Contracts[0].ID, projection.Contracts[0].TenantID, "contract_projection_"+suffix, tenantID)
	assertProjectionRecord(t, "VEXDocuments", projection.VEXDocuments[0].ID, projection.VEXDocuments[0].TenantID, "vex_projection_"+suffix, tenantID)
	assertProjectionRecord(t, "VEXImportReports", projection.VEXImportReports[0].ID, projection.VEXImportReports[0].TenantID, "report_projection_"+suffix, tenantID)
	assertProjectionRecord(t, "BuildAttestations", projection.BuildAttestations[0].ID, projection.BuildAttestations[0].TenantID, "attestation_projection_"+suffix, tenantID)
	assertProjectionRecord(t, "VulnerabilityDecisions", projection.VulnerabilityDecisions[0].ID, projection.VulnerabilityDecisions[0].TenantID, "decision_projection_"+suffix, tenantID)
	assertProjectionRecord(t, "AuditChainEntries", projection.AuditChainEntries[0].ID, projection.AuditChainEntries[0].TenantID, "chain_projection_"+suffix, tenantID)

	if got := projection.SBOMs[0].Components; len(got) != 1 || got[0].Name != "component-"+suffix {
		t.Fatalf("SBOM components = %#v", got)
	}
	if got := projection.Scans[0].Findings; len(got) != 1 || got[0].ID != "finding_projection_"+suffix {
		t.Fatalf("scan findings = %#v", got)
	}
	if got := projection.Contracts[0].Operations; len(got) != 1 || got[0].Path != "/"+suffix {
		t.Fatalf("contract operations = %#v", got)
	}
	if got := projection.VulnerabilityDecisions[0].EvidenceIDs; len(got) != 1 || got[0] != "ev_projection_"+suffix {
		t.Fatalf("decision evidence IDs = %#v", got)
	}
	if got := projection.AuditChainEntries[0].Metadata["suffix"]; got != suffix {
		t.Fatalf("audit metadata suffix = %#v, want %q", got, suffix)
	}
}

func assertProjectionRecord(t *testing.T, name, gotID, gotTenantID, wantID, wantTenantID string) {
	t.Helper()
	if gotID != wantID || gotTenantID != wantTenantID {
		t.Fatalf("%s identity = (%q, %q), want (%q, %q)", name, gotID, gotTenantID, wantID, wantTenantID)
	}
}
