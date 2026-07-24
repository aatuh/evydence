package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestMemoryUnitOfWorkRollbackDiscardsDomainAuditAndOutboxMutations(t *testing.T) {
	factory := NewMemoryUnitOfWorkFactory()
	uow, err := factory.BeginUnitOfWork(context.Background())
	if err != nil {
		t.Fatalf("begin unit of work: %v", err)
	}
	repositories := uow.Repositories()
	tenant := domain.Tenant{ID: "ten_rollback", Name: "Rollback", CreatedAt: fixedNow()}
	if err := repositories.Identity.InsertTenant(context.Background(), tenant); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := repositories.ReleaseCatalog.InsertProduct(context.Background(), domain.Product{ID: "prod_rollback", TenantID: tenant.ID, Name: "Rollback API", Slug: "rollback-api", CreatedAt: fixedNow()}); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	if _, err := repositories.Audit.Append(context.Background(), domain.AuditChainEntry{
		ID:          "ace_rollback",
		TenantID:    tenant.ID,
		EntryType:   "product.created",
		SubjectType: "product",
		SubjectID:   "prod_rollback",
		ActorType:   "system",
		ActorID:     "test",
		OccurredAt:  fixedNow(),
	}); err != nil {
		t.Fatalf("append audit: %v", err)
	}
	if err := repositories.Outbox.Enqueue(context.Background(), OutboxJob{ID: "job_rollback", TenantID: tenant.ID, Kind: "index_product", SubjectType: "product", SubjectID: "prod_rollback", CreatedAt: fixedNow()}); err != nil {
		t.Fatalf("enqueue outbox job: %v", err)
	}
	if err := uow.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	snapshot, err := factory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snapshot.Tenants) != 0 || len(snapshot.Products) != 0 || len(snapshot.AuditEntries) != 0 || len(snapshot.OutboxJobs) != 0 {
		t.Fatalf("rollback retained mutations: %#v", snapshot)
	}
}

func TestMemoryUnitOfWorkCommitsTenantScopedDomainAuditAndOutboxTogether(t *testing.T) {
	factory := NewMemoryUnitOfWorkFactory()
	uow, err := factory.BeginUnitOfWork(context.Background())
	if err != nil {
		t.Fatalf("begin unit of work: %v", err)
	}
	repositories := uow.Repositories()
	tenant := domain.Tenant{ID: "ten_commit", Name: "Commit", CreatedAt: fixedNow()}
	if err := repositories.Identity.InsertTenant(context.Background(), tenant); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	product := domain.Product{ID: "prod_commit", TenantID: tenant.ID, Name: "Commit API", Slug: "commit-api", CreatedAt: fixedNow()}
	if err := repositories.ReleaseCatalog.InsertProduct(context.Background(), product); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	entry, err := repositories.Audit.Append(context.Background(), domain.AuditChainEntry{
		ID:          "ace_commit",
		TenantID:    tenant.ID,
		EntryType:   "product.created",
		SubjectType: "product",
		SubjectID:   product.ID,
		ActorType:   "system",
		ActorID:     "test",
		OccurredAt:  fixedNow(),
	})
	if err != nil {
		t.Fatalf("append audit: %v", err)
	}
	if entry.Sequence != 1 || entry.PreviousEntryHash != "" || entry.EntryHash == "" {
		t.Fatalf("unexpected committed audit entry: %#v", entry)
	}
	if err := repositories.Outbox.Enqueue(context.Background(), OutboxJob{ID: "job_commit", TenantID: tenant.ID, Kind: "index_product", SubjectType: "product", SubjectID: product.ID, CreatedAt: fixedNow()}); err != nil {
		t.Fatalf("enqueue outbox job: %v", err)
	}
	if err := uow.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	snapshot, err := factory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := snapshot.Products[product.ID]; !ok || len(snapshot.AuditEntries[tenant.ID]) != 1 || len(snapshot.OutboxJobs) != 1 {
		t.Fatalf("commit did not publish all transaction mutations: %#v", snapshot)
	}
}

func TestMemoryUnitOfWorkRejectsCrossTenantProductReference(t *testing.T) {
	factory := NewMemoryUnitOfWorkFactory()
	seed, err := factory.BeginUnitOfWork(context.Background())
	if err != nil {
		t.Fatalf("begin seed unit of work: %v", err)
	}
	seedRepositories := seed.Repositories()
	if err := seedRepositories.Identity.InsertTenant(context.Background(), domain.Tenant{ID: "ten_a", Name: "A", CreatedAt: fixedNow()}); err != nil {
		t.Fatalf("insert tenant A: %v", err)
	}
	if err := seedRepositories.Identity.InsertTenant(context.Background(), domain.Tenant{ID: "ten_b", Name: "B", CreatedAt: fixedNow()}); err != nil {
		t.Fatalf("insert tenant B: %v", err)
	}
	if err := seedRepositories.ReleaseCatalog.InsertProduct(context.Background(), domain.Product{ID: "prod_a", TenantID: "ten_a", Name: "A API", Slug: "a-api", CreatedAt: fixedNow()}); err != nil {
		t.Fatalf("insert tenant A product: %v", err)
	}
	if err := seed.Commit(context.Background()); err != nil {
		t.Fatalf("commit seed unit of work: %v", err)
	}

	uow, err := factory.BeginUnitOfWork(context.Background())
	if err != nil {
		t.Fatalf("begin cross-tenant unit of work: %v", err)
	}
	err = uow.Repositories().ReleaseCatalog.InsertProject(context.Background(), domain.Project{ID: "proj_b", TenantID: "ten_b", ProductID: "prod_a", Name: "Cross tenant", CreatedAt: fixedNow()})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant project err=%v, want not found", err)
	}
	if err := uow.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback cross-tenant unit of work: %v", err)
	}
}

func TestExecuteUnitOfWorkRollsBackCommandFailure(t *testing.T) {
	factory := NewMemoryUnitOfWorkFactory()
	want := errors.New("command failed")
	err := ExecuteUnitOfWork(context.Background(), factory, func(ctx context.Context, repositories Repositories) error {
		if err := repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_failed_command", Name: "Failed command", CreatedAt: fixedNow()}); err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("command err=%v, want command failure", err)
	}
	snapshot, err := factory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snapshot.Tenants) != 0 {
		t.Fatalf("failed command committed state: %#v", snapshot.Tenants)
	}
}

func TestLedgerExecutesTransactionBackedCommandWithoutStateSave(t *testing.T) {
	factory := NewMemoryUnitOfWorkFactory()
	ledger := NewLedger(Config{APIKeyPepper: "test", Now: fixedNow, UnitOfWork: factory})
	err := ledger.ExecuteUnitOfWork(context.Background(), func(ctx context.Context, repositories Repositories) error {
		return repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_command", Name: "Transaction command", CreatedAt: fixedNow()})
	})
	if err != nil {
		t.Fatalf("execute transaction-backed command: %v", err)
	}
	snapshot, err := factory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := snapshot.Tenants["ten_command"]; !ok {
		t.Fatalf("transaction-backed command did not commit tenant: %#v", snapshot.Tenants)
	}
}

func TestMemoryUnitOfWorkCommitsEveryFocusedRepository(t *testing.T) {
	factory := NewMemoryUnitOfWorkFactory()
	uow, err := factory.BeginUnitOfWork(context.Background())
	if err != nil {
		t.Fatalf("begin unit of work: %v", err)
	}
	repositories := uow.Repositories()
	now := fixedNow()
	tenant := domain.Tenant{ID: "ten_all_repositories", Name: "All repositories", CreatedAt: now}
	if err := repositories.Identity.InsertTenant(context.Background(), tenant); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := repositories.Identity.InsertAPIKey(context.Background(), domain.APIKey{ID: "key_all_repositories", TenantID: tenant.ID, Name: "all repositories", Prefix: "evy_all", Hash: "hmac", Scopes: []string{"*"}, CreatedAt: now}); err != nil {
		t.Fatalf("insert API key: %v", err)
	}
	product := domain.Product{ID: "prod_all_repositories", TenantID: tenant.ID, Name: "All API", Slug: "all-api", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertProduct(context.Background(), product); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	project := domain.Project{ID: "proj_all_repositories", TenantID: tenant.ID, ProductID: product.ID, Name: "All project", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertProject(context.Background(), project); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	release := domain.Release{ID: "rel_all_repositories", TenantID: tenant.ID, ProductID: product.ID, Version: "1.0.0", State: "draft", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertRelease(context.Background(), release); err != nil {
		t.Fatalf("insert release: %v", err)
	}
	if err := repositories.ReleaseCatalog.InsertArtifact(context.Background(), domain.Artifact{ID: "art_all_repositories", TenantID: tenant.ID, Name: "all.tgz", MediaType: "application/gzip", Digest: "sha256:all", Size: 1, CreatedAt: now}); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}
	evidence := domain.EvidenceItem{ID: "evi_all_repositories", TenantID: tenant.ID, ProductID: product.ID, ProjectID: project.ID, ReleaseID: release.ID, Type: "sbom", Title: "All SBOM", PayloadHash: "sha256:payload", CanonicalHash: "sha256:canonical", CreatedAt: now, Metadata: map[string]any{"source": "test"}}
	if err := repositories.Evidence.InsertEvidence(context.Background(), evidence); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
	if err := repositories.Evidence.AppendLifecycle(context.Background(), domain.EvidenceLifecycleEvent{ID: "elc_all_repositories", TenantID: tenant.ID, EvidenceID: evidence.ID, Action: "accepted", Reason: "test", ActorID: "key_all_repositories", SchemaVersion: domain.EvidenceLifecycleSchemaVersion, CreatedAt: now, Details: map[string]any{"reason": "test"}}); err != nil {
		t.Fatalf("append lifecycle: %v", err)
	}
	if err := repositories.Decisions.InsertVulnerabilityDecision(context.Background(), domain.VulnerabilityDecision{ID: "dec_all_repositories", TenantID: tenant.ID, FindingID: "finding", ScanID: "scan", ReleaseID: release.ID, Vulnerability: "CVE-2026-0003", Status: "not_affected", Justification: "test", Source: "test", EvidenceID: evidence.ID, SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert decision: %v", err)
	}
	if _, err := repositories.Audit.Append(context.Background(), domain.AuditChainEntry{ID: "ace_all_repositories", TenantID: tenant.ID, EntryType: "evidence.created", SubjectType: "evidence_item", SubjectID: evidence.ID, ActorType: "system", ActorID: "test", OccurredAt: now}); err != nil {
		t.Fatalf("append audit: %v", err)
	}
	if err := repositories.Idempotency.Insert(context.Background(), IdempotencyRecordKey{TenantID: tenant.ID, ActorID: "key_all_repositories", Method: "POST", Path: "/v1/evidence", IdempotencyKey: "idem"}, IdempotencyRecord{RequestHash: "sha256:request", Status: 201, Response: map[string]any{"id": evidence.ID}, CreatedAt: now}); err != nil {
		t.Fatalf("insert idempotency: %v", err)
	}
	if err := repositories.Outbox.Enqueue(context.Background(), OutboxJob{ID: "job_all_repositories", TenantID: tenant.ID, Kind: "index_evidence", SubjectType: "evidence_item", SubjectID: evidence.ID, CreatedAt: now, Payload: map[string]any{"id": evidence.ID}}); err != nil {
		t.Fatalf("enqueue outbox: %v", err)
	}
	signingKey := domain.SigningKey{ID: "sigkey_all_repositories", TenantID: tenant.ID, KID: "all", Algorithm: "Ed25519", Status: "active", PublicKey: "public", Private: []byte("encrypted"), CreatedAt: now}
	if err := repositories.Signatures.InsertSigningKey(context.Background(), signingKey); err != nil {
		t.Fatalf("insert signing key: %v", err)
	}
	if err := repositories.Signatures.InsertSignature(context.Background(), domain.Signature{ID: "sig_all_repositories", TenantID: tenant.ID, SubjectType: "evidence_item", SubjectID: evidence.ID, KeyID: signingKey.ID, Algorithm: "Ed25519", Value: "signature", CreatedAt: now}); err != nil {
		t.Fatalf("insert signature: %v", err)
	}
	if err := repositories.Packages.InsertReleaseBundle(context.Background(), domain.ReleaseBundle{ID: "bundle_all_repositories", TenantID: tenant.ID, ReleaseID: release.ID, State: "generated", Manifest: map[string]any{"release_id": release.ID}, ManifestHash: "sha256:manifest", CreatedAt: now}); err != nil {
		t.Fatalf("insert release bundle: %v", err)
	}
	if err := repositories.Verification.InsertVerificationResult(context.Background(), domain.VerificationResult{ID: "verify_all_repositories", TenantID: tenant.ID, SubjectType: "evidence_item", SubjectID: evidence.ID, Result: "limited", VerifiedAt: now, Checks: []domain.VerifyCheck{{Name: "recorded", Result: "passed"}}}); err != nil {
		t.Fatalf("insert verification result: %v", err)
	}
	if err := uow.Commit(context.Background()); err != nil {
		t.Fatalf("commit all repositories: %v", err)
	}
	snapshot, err := factory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snapshot.APIKeys) != 1 || len(snapshot.Projects) != 1 || len(snapshot.Releases) != 1 || len(snapshot.Artifacts) != 1 || len(snapshot.Evidence) != 1 || len(snapshot.EvidenceLifecycle) != 1 || len(snapshot.Decisions) != 1 || len(snapshot.AuditEntries[tenant.ID]) != 1 || len(snapshot.Idempotency) != 1 || len(snapshot.OutboxJobs) != 1 || len(snapshot.ReleaseBundles) != 1 || len(snapshot.SigningKeys) != 1 || len(snapshot.Signatures) != 1 || len(snapshot.VerificationResults) != 1 {
		t.Fatalf("focused repositories did not commit together: %#v", snapshot)
	}
}

func TestMemoryUnitOfWorkRejectsInvalidFocusedRepositoryRecords(t *testing.T) {
	factory := NewMemoryUnitOfWorkFactory()
	uow, err := factory.BeginUnitOfWork(context.Background())
	if err != nil {
		t.Fatalf("begin unit of work: %v", err)
	}
	defer func() { _ = uow.Rollback(context.Background()) }()
	repositories := uow.Repositories()
	checks := []struct {
		name string
		err  error
	}{
		{"tenant", repositories.Identity.InsertTenant(context.Background(), domain.Tenant{})},
		{"API key", repositories.Identity.InsertAPIKey(context.Background(), domain.APIKey{})},
		{"product", repositories.ReleaseCatalog.InsertProduct(context.Background(), domain.Product{})},
		{"project", repositories.ReleaseCatalog.InsertProject(context.Background(), domain.Project{})},
		{"release", repositories.ReleaseCatalog.InsertRelease(context.Background(), domain.Release{})},
		{"artifact", repositories.ReleaseCatalog.InsertArtifact(context.Background(), domain.Artifact{})},
		{"evidence", repositories.Evidence.InsertEvidence(context.Background(), domain.EvidenceItem{})},
		{"lifecycle", repositories.Evidence.AppendLifecycle(context.Background(), domain.EvidenceLifecycleEvent{})},
		{"decision", repositories.Decisions.InsertVulnerabilityDecision(context.Background(), domain.VulnerabilityDecision{})},
		{"idempotency", repositories.Idempotency.Insert(context.Background(), IdempotencyRecordKey{}, IdempotencyRecord{})},
		{"outbox", repositories.Outbox.Enqueue(context.Background(), OutboxJob{})},
		{"package", repositories.Packages.InsertReleaseBundle(context.Background(), domain.ReleaseBundle{})},
		{"signing key", repositories.Signatures.InsertSigningKey(context.Background(), domain.SigningKey{})},
		{"signature", repositories.Signatures.InsertSignature(context.Background(), domain.Signature{})},
		{"verification", repositories.Verification.InsertVerificationResult(context.Background(), domain.VerificationResult{})},
	}
	for _, check := range checks {
		if !errors.Is(check.err, ErrValidation) {
			t.Errorf("%s err=%v, want validation", check.name, check.err)
		}
	}
	if _, err := repositories.Audit.Append(context.Background(), domain.AuditChainEntry{}); !errors.Is(err, ErrValidation) {
		t.Fatalf("audit err=%v, want validation", err)
	}
}

func TestMemoryUnitOfWorkRejectsStaleTransactionsAndUnownedReferences(t *testing.T) {
	factory := NewMemoryUnitOfWorkFactory()
	stale, err := factory.BeginUnitOfWork(context.Background())
	if err != nil {
		t.Fatalf("begin stale unit of work: %v", err)
	}
	committed, err := factory.BeginUnitOfWork(context.Background())
	if err != nil {
		t.Fatalf("begin committed unit of work: %v", err)
	}
	if err := committed.Repositories().Identity.InsertTenant(context.Background(), domain.Tenant{ID: "ten_committed_uow", Name: "Committed", CreatedAt: fixedNow()}); err != nil {
		t.Fatalf("insert committed tenant: %v", err)
	}
	if err := committed.Commit(context.Background()); err != nil {
		t.Fatalf("commit current transaction: %v", err)
	}
	if err := committed.Commit(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("second commit err=%v, want conflict", err)
	}
	if err := stale.Repositories().Identity.InsertTenant(context.Background(), domain.Tenant{ID: "ten_stale_uow", Name: "Stale", CreatedAt: fixedNow()}); err != nil {
		t.Fatalf("insert stale tenant: %v", err)
	}
	if err := stale.Commit(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale commit err=%v, want conflict", err)
	}
	if err := stale.Rollback(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale rollback err=%v, want conflict", err)
	}

	uow, err := factory.BeginUnitOfWork(context.Background())
	if err != nil {
		t.Fatalf("begin ownership unit of work: %v", err)
	}
	defer func() { _ = uow.Rollback(context.Background()) }()
	repositories := uow.Repositories()
	if err := repositories.ReleaseCatalog.InsertArtifact(context.Background(), domain.Artifact{ID: "art_missing_tenant", TenantID: "ten_missing", Name: "missing", MediaType: "application/octet-stream", Digest: "sha256:missing", CreatedAt: fixedNow()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tenant artifact err=%v, want not found", err)
	}
	if err := repositories.Evidence.InsertEvidence(context.Background(), domain.EvidenceItem{ID: "evi_missing_product", TenantID: "ten_committed_uow", ProductID: "prod_missing", Type: "note", Title: "Missing product", PayloadHash: "sha256:payload", CanonicalHash: "sha256:canonical", CreatedAt: fixedNow()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing product evidence err=%v, want not found", err)
	}
	if err := repositories.Signatures.InsertSignature(context.Background(), domain.Signature{ID: "sig_missing_key", TenantID: "ten_committed_uow", SubjectType: "evidence", SubjectID: "evi", KeyID: "key_missing", Algorithm: "Ed25519", Value: "signature", CreatedAt: fixedNow()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing signing key err=%v, want not found", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := factory.BeginUnitOfWork(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled begin err=%v, want canceled", err)
	}
	if err := ExecuteUnitOfWork(context.Background(), nil, func(context.Context, Repositories) error { return nil }); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil factory err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(context.Background(), factory, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil command err=%v, want validation", err)
	}
	if err := ExecuteUnitOfWork(canceled, factory, func(context.Context, Repositories) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled command err=%v, want canceled", err)
	}
}
