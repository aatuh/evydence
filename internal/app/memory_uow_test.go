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
	artifact := domain.Artifact{ID: "art_all_repositories", TenantID: tenant.ID, Name: "all.tgz", MediaType: "application/gzip", Digest: "sha256:all", Size: 1, CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertArtifact(context.Background(), artifact); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}
	image := domain.ContainerImage{ID: "image_all_repositories", TenantID: tenant.ID, ArtifactID: artifact.ID, Repository: "registry.example.test/all", Digest: artifact.Digest, SchemaVersion: domain.ContainerImageSchemaVersion, CreatedAt: now}
	if err := repositories.SupplyChain.InsertContainerImage(context.Background(), image); err != nil {
		t.Fatalf("insert container image: %v", err)
	}
	artifactSignature := domain.ArtifactSignature{ID: "artifact_signature_all_repositories", TenantID: tenant.ID, ArtifactID: artifact.ID, SubjectDigest: artifact.Digest, Algorithm: "cosign", Signature: "signature", VerificationStatus: "recorded", SchemaVersion: domain.ArtifactSignatureSchemaVersion, CreatedAt: now}
	if err := repositories.SupplyChain.InsertArtifactSignature(context.Background(), artifactSignature); err != nil {
		t.Fatalf("insert artifact signature: %v", err)
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
	if err := repositories.Integrity.InsertSigningProvider(context.Background(), domain.SigningProvider{ID: "provider_all_repositories", TenantID: tenant.ID, Name: "All repositories KMS", Type: "aws_kms", Status: "active", KeyRef: "arn:aws:kms:example", Encrypted: true, SchemaVersion: domain.SigningProviderSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert signing provider: %v", err)
	}
	if err := repositories.Future.InsertPublicTransparencyLog(context.Background(), domain.PublicTransparencyLog{ID: "public_log_all_repositories", TenantID: tenant.ID, Name: "All repositories log", Endpoint: "https://transparency.example.test", PublicKey: "public-key", State: "configured", SchemaVersion: domain.PublicTransparencyLogVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert public transparency log: %v", err)
	}
	if err := repositories.Future.InsertEvidenceSummary(context.Background(), domain.EvidenceSummary{ID: "summary_all_repositories", TenantID: tenant.ID, SubjectType: "release", SubjectID: release.ID, EvidenceIDs: []string{evidence.ID}, Summary: "All repository evidence", Citations: []domain.EvidenceCitation{{EvidenceID: evidence.ID, Type: evidence.Type, Title: evidence.Title, CanonicalHash: evidence.CanonicalHash}}, SchemaVersion: domain.EvidenceSummaryVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert evidence summary: %v", err)
	}
	if err := repositories.Future.InsertEvidenceGraphSnapshot(context.Background(), domain.EvidenceGraphSnapshot{ID: "graph_all_repositories", TenantID: tenant.ID, ProductID: product.ID, ReleaseID: release.ID, Nodes: []domain.GraphNode{}, Edges: []domain.GraphEdge{}, GraphHash: "sha256:graph", SchemaVersion: domain.EvidenceGraphSnapshotVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert evidence graph snapshot: %v", err)
	}
	if err := repositories.Future.InsertSaaSEditionProfile(context.Background(), domain.SaaSEditionProfile{ID: "saas_all_repositories", TenantID: tenant.ID, Name: "All repositories", Region: "eu", AdminTenantID: tenant.ID, IsolationModel: "shared-control-plane", Status: "proposed", ConfigHash: "sha256:config", SchemaVersion: domain.SaaSEditionProfileVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert SaaS edition profile: %v", err)
	}
	if err := repositories.Future.InsertMarketplaceCollector(context.Background(), domain.MarketplaceCollector{ID: "marketplace_all_repositories", TenantID: tenant.ID, Name: "All repositories", Provider: "scanner", Version: "1.0.0", Publisher: "vendor", ManifestHash: "sha256:manifest", State: "registered", SchemaVersion: domain.MarketplaceCollectorVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert marketplace collector: %v", err)
	}
	if err := repositories.Future.InsertPDFReportPackage(context.Background(), domain.PDFReportPackage{ID: "pdf_all_repositories", TenantID: tenant.ID, ReportType: "release_readiness", ProductID: product.ID, ReleaseID: release.ID, Title: "All repositories", PayloadHash: "sha256:report", PayloadSize: 1, SchemaVersion: domain.PDFReportPackageVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert PDF report package: %v", err)
	}
	if err := repositories.Integrity.InsertCosignVerification(context.Background(), domain.CosignVerification{ID: "cosign_all_repositories", TenantID: tenant.ID, ArtifactID: artifact.ID, ContainerImageID: image.ID, ArtifactSignatureID: artifactSignature.ID, SubjectDigest: artifact.Digest, Result: "limited", Checks: []domain.VerifyCheck{{Name: "recorded", Result: "passed"}}, SchemaVersion: domain.CosignVerificationSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert Cosign verification: %v", err)
	}
	retentionPolicy := domain.ObjectRetentionPolicy{ID: "retention_all_repositories", TenantID: tenant.ID, Name: "All repository retention", ObjectPrefix: "tenants/" + tenant.ID + "/", ObjectKey: "tenants/" + tenant.ID + "/raw/evidence.json", Mode: "governance", RetentionDays: 30, MaxVerificationAgeHours: 24, Status: "configured", SchemaVersion: domain.ObjectRetentionPolicyVersion, CreatedAt: now}
	if err := repositories.Integrity.InsertObjectRetentionPolicy(context.Background(), retentionPolicy); err != nil {
		t.Fatalf("insert object retention policy: %v", err)
	}
	retentionPolicy.Status = "not_verified"
	retentionPolicy.VerifiedAt = &now
	retentionPolicy.VerificationHash = "sha256:retention"
	retentionPolicy.VerificationChecks = []domain.VerifyCheck{{Name: "recorded", Result: "passed"}}
	if err := repositories.Integrity.UpdateObjectRetentionPolicy(context.Background(), retentionPolicy, "configured"); err != nil {
		t.Fatalf("update object retention policy: %v", err)
	}
	if err := repositories.Integrity.InsertBackupManifest(context.Background(), domain.BackupManifest{ID: "backup_all_repositories", TenantID: tenant.ID, StateHash: "sha256:backup", ResourceCounts: map[string]int{"evidence": 1}, ConsistencyChecks: []domain.VerifyCheck{{Name: "chain", Result: "passed"}}, SchemaVersion: domain.BackupManifestSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert backup manifest: %v", err)
	}
	merkleBatch := domain.MerkleBatch{ID: "merkle_all_repositories", TenantID: tenant.ID, FromSequence: 1, ToSequence: 1, EntryCount: 1, LeafHashes: []string{"sha256:leaf"}, RootHash: "sha256:root", SchemaVersion: domain.MerkleBatchSchemaVersion, CreatedAt: now}
	if err := repositories.Integrity.InsertMerkleBatch(context.Background(), merkleBatch); err != nil {
		t.Fatalf("insert Merkle batch: %v", err)
	}
	if err := repositories.Integrity.InsertTransparencyCheckpoint(context.Background(), domain.TransparencyCheckpoint{ID: "checkpoint_all_repositories", TenantID: tenant.ID, BatchID: merkleBatch.ID, Provider: "rfc3161", ExternalID: "checkpoint", TimestampHash: "sha256:checkpoint", State: "recorded", SchemaVersion: domain.TransparencyCheckpointVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert transparency checkpoint: %v", err)
	}
	if err := repositories.Future.InsertPublicTransparencyLogEntry(context.Background(), domain.PublicTransparencyLogEntry{ID: "public_entry_all_repositories", TenantID: tenant.ID, LogID: "public_log_all_repositories", CheckpointID: "checkpoint_all_repositories", MerkleBatchID: merkleBatch.ID, ExternalID: "entry", EntryHash: "sha256:entry", State: "published", SchemaVersion: domain.PublicTransparencyEntryVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert public transparency entry: %v", err)
	}
	verifiedPublicEntry := domain.PublicTransparencyLogEntry{ID: "public_entry_all_repositories", TenantID: tenant.ID, LogID: "public_log_all_repositories", CheckpointID: "checkpoint_all_repositories", MerkleBatchID: merkleBatch.ID, ExternalID: "entry", EntryHash: "sha256:entry", State: "inclusion_verified", InclusionRootHash: "sha256:root", InclusionProofHash: "sha256:proof", InclusionVerifiedAt: &now, VerificationChecks: []domain.VerifyCheck{{Name: "proof", Result: "passed"}}, SchemaVersion: domain.PublicTransparencyEntryVersion, CreatedAt: now}
	if err := repositories.Future.UpdatePublicTransparencyLogEntry(context.Background(), verifiedPublicEntry, "published"); err != nil {
		t.Fatalf("update public transparency entry: %v", err)
	}
	if err := repositories.Packages.InsertReleaseBundle(context.Background(), domain.ReleaseBundle{ID: "bundle_all_repositories", TenantID: tenant.ID, ReleaseID: release.ID, State: "generated", Manifest: map[string]any{"release_id": release.ID}, ManifestHash: "sha256:manifest", CreatedAt: now}); err != nil {
		t.Fatalf("insert release bundle: %v", err)
	}
	if err := repositories.Verification.InsertVerificationResult(context.Background(), domain.VerificationResult{ID: "verify_all_repositories", TenantID: tenant.ID, SubjectType: "evidence_item", SubjectID: evidence.ID, Result: "limited", VerifiedAt: now, Checks: []domain.VerifyCheck{{Name: "recorded", Result: "passed"}}}); err != nil {
		t.Fatalf("insert verification result: %v", err)
	}
	if err := repositories.Verification.InsertPolicyEvaluation(context.Background(), domain.PolicyEvaluation{ID: "policy_all_repositories", TenantID: tenant.ID, ReleaseID: release.ID, Result: "passed", PolicySet: domain.PolicySetVersion, Checks: []domain.PolicyCheck{{Name: "recorded", Result: "passed", Severity: "low", Explanation: "test"}}, CreatedAt: now}); err != nil {
		t.Fatalf("insert policy evaluation: %v", err)
	}
	if err := uow.Commit(context.Background()); err != nil {
		t.Fatalf("commit all repositories: %v", err)
	}
	snapshot, err := factory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snapshot.APIKeys) != 1 || len(snapshot.Projects) != 1 || len(snapshot.Releases) != 1 || len(snapshot.Artifacts) != 1 || len(snapshot.ContainerImages) != 1 || len(snapshot.ArtifactSignatures) != 1 || len(snapshot.Evidence) != 1 || len(snapshot.EvidenceLifecycle) != 1 || len(snapshot.Decisions) != 1 || len(snapshot.AuditEntries[tenant.ID]) != 1 || len(snapshot.Idempotency) != 1 || len(snapshot.OutboxJobs) != 1 || len(snapshot.ReleaseBundles) != 1 || len(snapshot.SigningKeys) != 1 || len(snapshot.Signatures) != 1 || len(snapshot.SigningProviders) != 1 || len(snapshot.CosignVerifications) != 1 || len(snapshot.ObjectRetentionPolicies) != 1 || len(snapshot.BackupManifests) != 1 || len(snapshot.MerkleBatches) != 1 || len(snapshot.TransparencyCheckpoints) != 1 || len(snapshot.VerificationResults) != 1 || len(snapshot.PolicyEvaluations) != 1 || len(snapshot.PublicTransparencyLogs) != 1 || len(snapshot.PublicTransparencyEntries) != 1 || len(snapshot.EvidenceSummaries) != 1 || len(snapshot.EvidenceGraphSnapshots) != 1 || len(snapshot.SaaSEditionProfiles) != 1 || len(snapshot.MarketplaceCollectors) != 1 || len(snapshot.PDFReports) != 1 {
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
		{"signing key update", repositories.Signatures.UpdateSigningKey(context.Background(), domain.SigningKey{}, "")},
		{"signature", repositories.Signatures.InsertSignature(context.Background(), domain.Signature{})},
		{"signing provider", repositories.Integrity.InsertSigningProvider(context.Background(), domain.SigningProvider{})},
		{"Cosign verification", repositories.Integrity.InsertCosignVerification(context.Background(), domain.CosignVerification{})},
		{"object retention policy", repositories.Integrity.InsertObjectRetentionPolicy(context.Background(), domain.ObjectRetentionPolicy{})},
		{"object retention policy update", repositories.Integrity.UpdateObjectRetentionPolicy(context.Background(), domain.ObjectRetentionPolicy{}, "")},
		{"backup manifest", repositories.Integrity.InsertBackupManifest(context.Background(), domain.BackupManifest{})},
		{"Merkle batch", repositories.Integrity.InsertMerkleBatch(context.Background(), domain.MerkleBatch{})},
		{"transparency checkpoint", repositories.Integrity.InsertTransparencyCheckpoint(context.Background(), domain.TransparencyCheckpoint{})},
		{"public transparency log", repositories.Future.InsertPublicTransparencyLog(context.Background(), domain.PublicTransparencyLog{})},
		{"public transparency entry", repositories.Future.InsertPublicTransparencyLogEntry(context.Background(), domain.PublicTransparencyLogEntry{})},
		{"public transparency entry update", repositories.Future.UpdatePublicTransparencyLogEntry(context.Background(), domain.PublicTransparencyLogEntry{}, "")},
		{"evidence summary", repositories.Future.InsertEvidenceSummary(context.Background(), domain.EvidenceSummary{})},
		{"evidence graph snapshot", repositories.Future.InsertEvidenceGraphSnapshot(context.Background(), domain.EvidenceGraphSnapshot{})},
		{"SaaS edition profile", repositories.Future.InsertSaaSEditionProfile(context.Background(), domain.SaaSEditionProfile{})},
		{"marketplace collector", repositories.Future.InsertMarketplaceCollector(context.Background(), domain.MarketplaceCollector{})},
		{"PDF report package", repositories.Future.InsertPDFReportPackage(context.Background(), domain.PDFReportPackage{})},
		{"verification", repositories.Verification.InsertVerificationResult(context.Background(), domain.VerificationResult{})},
		{"policy evaluation", repositories.Verification.InsertPolicyEvaluation(context.Background(), domain.PolicyEvaluation{})},
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
