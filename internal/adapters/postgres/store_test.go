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

func TestResolveLoadMode(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		production bool
		want       LoadMode
		wantErr    bool
	}{
		{name: "local default", want: LoadModeSnapshotPreferred},
		{name: "production default", production: true, want: LoadModeRelationalOnly},
		{name: "snapshot alias", raw: "snapshot", production: true, want: LoadModeSnapshotPreferred},
		{name: "relational alias", raw: "relational", want: LoadModeRelationalPreferred},
		{name: "relational only", raw: "relational-only", want: LoadModeRelationalOnly},
		{name: "invalid", raw: "unsafe", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveLoadMode(tt.raw, tt.production)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveLoadMode: %v", err)
			}
			if got != tt.want {
				t.Fatalf("mode = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateProductionLoadModeRequiresRelationalOnly(t *testing.T) {
	if err := ValidateProductionLoadMode(LoadModeRelationalOnly); err != nil {
		t.Fatalf("relational-only production mode: %v", err)
	}
	for _, mode := range []LoadMode{LoadModeSnapshotPreferred, LoadModeRelationalPreferred} {
		err := ValidateProductionLoadMode(mode)
		if err == nil || !strings.Contains(err.Error(), "EVYDENCE_POSTGRES_LOAD_MODE") {
			t.Fatalf("%s production err=%v", mode, err)
		}
	}
}

func TestStoreCanDisableSnapshotWritesAndLoadRelationalState(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_snapshot_disabled_" + strings.ReplaceAll(strings.ToLower(time.Now().Format("20060102150405.000000000")), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = admin.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{LoadMode: LoadModeRelationalPreferred, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	state := app.PersistedState{
		Tenants: map[string]domain.Tenant{
			"ten_snapshot_disabled": {ID: "ten_snapshot_disabled", Name: "No Snapshot", CreatedAt: time.Now().UTC()},
		},
		Products: map[string]domain.Product{
			"prod_snapshot_disabled": {ID: "prod_snapshot_disabled", TenantID: "ten_snapshot_disabled", Name: "Relational Product", Slug: "relational-product", CreatedAt: time.Now().UTC()},
		},
	}
	if err := store.SaveState(ctx, state); err != nil {
		t.Fatal(err)
	}
	var snapshotRows int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM ledger_state`).Scan(&snapshotRows); err != nil {
		t.Fatal(err)
	}
	if snapshotRows != 0 {
		t.Fatalf("ledger_state rows = %d, want 0", snapshotRows)
	}
	loaded, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load relational state ok=%v err=%v", ok, err)
	}
	if loaded.Products["prod_snapshot_disabled"].Name != "Relational Product" {
		t.Fatalf("loaded products = %#v", loaded.Products)
	}
}

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
		Collectors: map[string]domain.Collector{
			"collector_test": {ID: "collector_test", TenantID: "ten_test", Name: "github", Type: "github_actions", Version: "1.0.0", APIKeyID: "key_test", Status: "active", AllowedScopes: []string{"build:write"}, LastSeenAt: ptrTime(time.Now().UTC()), SchemaVersion: domain.CollectorSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		CollectorReleases: map[string]domain.CollectorRelease{
			"collector_release_test": {ID: "collector_release_test", TenantID: "ten_test", CollectorID: "collector_test", Version: "1.0.0", ArtifactDigest: "sha256:" + strings.Repeat("a", 64), SignatureID: "artsig_test", SBOMID: "sbom_test", ScanID: "scan_test", Pinned: true, VerificationStatus: "verified", HealthStatus: "healthy", Limitations: []string{"test"}, SchemaVersion: domain.CollectorReleaseSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		SSOProviders: map[string]domain.SSOProvider{
			"sso_test": {ID: "sso_test", TenantID: "ten_test", Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client", Status: "active", JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "kid-1", "crv": "Ed25519", "x": "abc"}}}, SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: time.Now().UTC(), TrustMaterialUpdatedAt: ptrTime(time.Now().UTC())},
		},
		IdentityLinks: map[string]domain.UserIdentityLink{
			"link_test": {ID: "link_test", TenantID: "ten_test", UserID: "user_test", ProviderID: "sso_test", Subject: "sub", Email: "user@example.test", Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: time.Now().UTC()},
		},
		SSOSessions: map[string]domain.SSOSession{
			"sess_test": {ID: "sess_test", TenantID: "ten_test", UserID: "user_test", ProviderID: "sso_test", Prefix: "sess", Groups: []string{"security"}, ExpiresAt: time.Now().UTC().Add(time.Hour), SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		SSOSessionHashes: map[string]string{"sess_test": "session-hash"},
		CustomerPortalAccess: map[string]domain.CustomerPortalAccess{
			"cpa_test": {ID: "cpa_test", TenantID: "ten_test", PackageID: "pkg_test", CustomerName: "Customer", Prefix: "evycp_test", ExpiresAt: time.Now().UTC().Add(time.Hour), AccessCount: 2, FailedAccessCount: 1, LastAccessedAt: ptrTime(time.Now().UTC()), LastFailedAt: ptrTime(time.Now().UTC()), SchemaVersion: domain.CustomerPortalAccessVersion, CreatedAt: time.Now().UTC()},
		},
		CustomerPortalHashes: map[string]string{"cpa_test": "portal-token-hash"},
		Products: map[string]domain.Product{
			"prod_test": {ID: "prod_test", TenantID: "ten_test", Name: "Product", Slug: "product", CreatedAt: time.Now().UTC()},
		},
		Projects: map[string]domain.Project{
			"proj_test": {ID: "proj_test", TenantID: "ten_test", ProductID: "prod_test", Name: "API", CreatedAt: time.Now().UTC()},
		},
		Releases: map[string]domain.Release{
			"rel_test": {ID: "rel_test", TenantID: "ten_test", ProductID: "prod_test", Version: "1.0.0", State: "open", CreatedAt: time.Now().UTC()},
		},
		Artifacts: map[string]domain.Artifact{
			"art_test": {ID: "art_test", TenantID: "ten_test", Name: "artifact.tar.gz", MediaType: "application/gzip", Size: 42, Digest: "sha256:" + strings.Repeat("a", 64), CreatedAt: time.Now().UTC()},
		},
		BuildRuns: map[string]domain.BuildRun{
			"build_test": {ID: "build_test", TenantID: "ten_test", ProjectID: "proj_test", ReleaseID: "rel_test", CollectorID: "collector_test", Provider: "github_actions", CommitSHA: strings.Repeat("1", 40), Repository: "org/repo", WorkflowRef: "org/repo/.github/workflows/ci.yml@refs/heads/main", RunID: "123", RunAttempt: 1, Status: "passed", StartedAt: time.Now().UTC(), FinishedAt: ptrTime(time.Now().UTC()), SourceIdentity: map[string]any{"provider": "github_actions"}, Outputs: []domain.BuildOutput{{ArtifactID: "art_test", Digest: "sha256:" + strings.Repeat("a", 64)}}, SchemaVersion: domain.BuildRunSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		BuildAttestations: map[string]domain.BuildAttestation{
			"att_test": {ID: "att_test", TenantID: "ten_test", BuildID: "build_test", EvidenceID: "ev_test", PayloadRef: "object://tenants/ten_test/payloads/attestation/" + strings.Repeat("a", 64), PayloadHash: "sha256:" + strings.Repeat("a", 64), PayloadSize: 100, PayloadType: "application/vnd.dsse.envelope.v1+json", PredicateType: "https://slsa.dev/provenance/v1", SubjectDigests: []string{"sha256:" + strings.Repeat("a", 64)}, BuilderID: "builder", BuildType: "github_actions", MaterialsCount: 1, SignatureCount: 1, VerificationStatus: "structurally_valid", SchemaVersion: domain.BuildAttestationSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Evidence: map[string]domain.EvidenceItem{
			"ev_test": {
				ID: "ev_test", TenantID: "ten_test", ProductID: "prod_test", ProjectID: "proj_test", ReleaseID: "rel_test",
				Type: "sbom", Subtype: "cyclonedx", Title: "SBOM", SourceSystem: "test", ObservedAt: time.Now().UTC(),
				EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadRef: "object://tenants/ten_test/payloads/sbom/" + strings.Repeat("b", 64),
				PayloadHash: "sha256:" + strings.Repeat("b", 64), PayloadMediaType: "application/json", PayloadSize: 123,
				CanonicalHash: "sha256:" + strings.Repeat("c", 64), Canonicalization: domain.CanonicalizationProfileVersion,
				SubjectRefs: []domain.SubjectRef{{Type: "release", ID: "rel_test"}}, TrustLevel: "uploaded", VerificationStatus: "verified",
				Tags: []string{"release"}, Metadata: map[string]any{"parser": "test"}, CreatedAt: time.Now().UTC(),
			},
		},
		EvidenceLifecycle: map[string]domain.EvidenceLifecycleEvent{
			"life_test": {ID: "life_test", TenantID: "ten_test", EvidenceID: "ev_test", Action: "amended", Reason: "test", Details: map[string]any{"field": "metadata"}, ActorID: "user_test", SchemaVersion: domain.EvidenceLifecycleSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		ReleaseCandidates: map[string]domain.ReleaseCandidate{
			"rc_test": {ID: "rc_test", TenantID: "ten_test", ReleaseID: "rel_test", Name: "rc1", State: "open", BuildIDs: []string{"build_test"}, ArtifactIDs: []string{"art_test"}, SBOMIDs: []string{"sbom_test"}, ScanIDs: []string{"scan_test"}, VEXIDs: []string{"vex_test"}, ContractIDs: []string{"contract_test"}, BundleIDs: []string{"bundle_test"}, SnapshotHash: "sha256:" + strings.Repeat("0", 64), SchemaVersion: domain.ReleaseCandidateSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		ContainerImages: map[string]domain.ContainerImage{
			"image_test": {ID: "image_test", TenantID: "ten_test", ArtifactID: "art_test", Repository: "registry.example.test/product", Tag: "1.0.0", Digest: "sha256:" + strings.Repeat("a", 64), Platform: "linux/amd64", SchemaVersion: domain.ContainerImageSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		ArtifactSignatures: map[string]domain.ArtifactSignature{
			"artsig_test": {ID: "artsig_test", TenantID: "ten_test", ArtifactID: "art_test", SubjectDigest: "sha256:" + strings.Repeat("a", 64), Algorithm: "cosign", KeyID: "sigkey_test", Signature: "signature", PayloadRef: "object://tenants/ten_test/signatures/art", PayloadHash: "sha256:" + strings.Repeat("a", 64), VerificationStatus: "verified", SchemaVersion: domain.ArtifactSignatureSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Repositories: map[string]domain.SourceRepository{
			"repo_test": {ID: "repo_test", TenantID: "ten_test", ProjectID: "proj_test", Provider: "github", FullName: "org/repo", CloneURL: "https://github.com/org/repo.git", DefaultBranch: "main", SchemaVersion: domain.SourceRepositorySchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Commits: map[string]domain.SourceCommit{
			"commit_test": {ID: "commit_test", TenantID: "ten_test", RepositoryID: "repo_test", SHA: strings.Repeat("1", 40), Author: "tester", MessageHash: "sha256:" + strings.Repeat("2", 64), CommittedAt: time.Now().UTC(), SchemaVersion: domain.SourceCommitSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Branches: map[string]domain.SourceBranch{
			"branch_test": {ID: "branch_test", TenantID: "ten_test", RepositoryID: "repo_test", Name: "main", HeadCommitID: "commit_test", Protected: true, ProtectionHash: "sha256:" + strings.Repeat("3", 64), SchemaVersion: domain.SourceBranchSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		PullRequests: map[string]domain.PullRequest{
			"pr_test": {ID: "pr_test", TenantID: "ten_test", RepositoryID: "repo_test", Provider: "github", ProviderID: "42", Title: "Change", State: "merged", SourceBranch: "feature", TargetBranch: "main", HeadCommitID: "commit_test", ReviewDecision: "approved", SchemaVersion: domain.PullRequestSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Environments: map[string]domain.DeploymentEnvironment{
			"env_test": {ID: "env_test", TenantID: "ten_test", ProductID: "prod_test", Name: "production", Kind: "production", SchemaVersion: domain.DeploymentEnvironmentVersion, CreatedAt: time.Now().UTC()},
		},
		Deployments: map[string]domain.DeploymentEvent{
			"deploy_test": {ID: "deploy_test", TenantID: "ten_test", EnvironmentID: "env_test", ReleaseID: "rel_test", ArtifactIDs: []string{"art_test"}, Status: "succeeded", StartedAt: time.Now().UTC(), FinishedAt: ptrTime(time.Now().UTC()), EvidenceID: "ev_test", SchemaVersion: domain.DeploymentEventSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Incidents: map[string]domain.Incident{
			"incident_test": {ID: "incident_test", TenantID: "ten_test", ProductID: "prod_test", ReleaseID: "rel_test", Title: "Incident", Severity: "medium", Status: "resolved", OpenedAt: time.Now().UTC(), ClosedAt: ptrTime(time.Now().UTC()), SchemaVersion: domain.IncidentSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		TimelineEvents: map[string]domain.IncidentTimelineEvent{
			"timeline_test": {ID: "timeline_test", TenantID: "ten_test", IncidentID: "incident_test", EventType: "detected", Summary: "detected", EvidenceID: "ev_test", OccurredAt: time.Now().UTC(), SchemaVersion: domain.IncidentTimelineSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		IncidentWebhookReceivers: map[string]domain.IncidentWebhookReceiver{
			"receiver_test": {ID: "receiver_test", TenantID: "ten_test", IncidentID: "incident_test", Name: "pager", Provider: "generic", PublicKey: "pub", Status: "active", SchemaVersion: domain.IncidentWebhookReceiverVersion, CreatedAt: time.Now().UTC()},
		},
		IncidentWebhookEvents: map[string]domain.IncidentWebhookEvent{
			"webhook_event_test": {ID: "webhook_event_test", TenantID: "ten_test", ReceiverID: "receiver_test", IncidentID: "incident_test", Provider: "generic", EventID: "evt-1", PayloadHash: "sha256:" + strings.Repeat("a", 64), SignatureHash: "sha256:" + strings.Repeat("b", 64), TimelineEventID: "timeline_test", Result: "accepted", SchemaVersion: domain.IncidentWebhookEventVersion, CreatedAt: time.Now().UTC()},
		},
		RemediationTasks: map[string]domain.RemediationTask{
			"remediation_test": {ID: "remediation_test", TenantID: "ten_test", IncidentID: "incident_test", ReleaseID: "rel_test", Title: "Patch", Owner: "security", Status: "done", DueAt: ptrTime(time.Now().UTC().Add(24 * time.Hour)), EvidenceID: "ev_test", SchemaVersion: domain.RemediationTaskSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		SecurityScans: map[string]domain.SecurityScan{
			"secscan_test": {ID: "secscan_test", TenantID: "ten_test", ProductID: "prod_test", ReleaseID: "rel_test", ArtifactID: "art_test", Category: "sast", Format: "sarif", Scanner: "scanner", TargetRef: "repo", EvidenceID: "ev_test", PayloadRef: "object://tenants/ten_test/security/sarif", PayloadHash: "sha256:" + strings.Repeat("c", 64), FindingCount: 1, Summary: map[string]int{"high": 1}, Redacted: true, SchemaVersion: domain.SecurityScanSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		ManualSecurityDocs: map[string]domain.ManualSecurityDocument{
			"manual_doc_test": {ID: "manual_doc_test", TenantID: "ten_test", ProductID: "prod_test", ReleaseID: "rel_test", DocumentType: "security_review", Title: "Review", Sensitivity: "restricted", EvidenceID: "ev_test", PayloadRef: "object://tenants/ten_test/manual/review", PayloadHash: "sha256:" + strings.Repeat("d", 64), SchemaVersion: domain.ManualSecurityDocSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		SBOMDiffs: map[string]domain.SBOMDiff{
			"sbomdiff_test": {ID: "sbomdiff_test", TenantID: "ten_test", BaseSBOMID: "sbom_test", TargetSBOMID: "sbom_test", ReleaseID: "rel_test", AddedComponents: []domain.SBOMComponent{{Name: "lib2"}}, UnchangedCount: 1, SchemaVersion: domain.SBOMDiffSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		DependencyChanges: map[string]domain.DependencyChange{
			"depchange_test": {ID: "depchange_test", TenantID: "ten_test", SBOMDiffID: "sbomdiff_test", ChangeType: "added", Component: domain.SBOMComponent{Name: "lib2"}, SchemaVersion: domain.DependencyChangeSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		VulnerabilityWorkflow: map[string]domain.VulnerabilityWorkflowRecord{
			"vulnwf_test": {ID: "vulnwf_test", TenantID: "ten_test", FindingID: "finding_test", ReleaseID: "rel_test", Action: "reopened", Reason: "new evidence", ActorID: "user_test", SchemaVersion: "vulnerability-workflow.v1.0.0", CreatedAt: time.Now().UTC()},
		},
		ContractDiffs: map[string]domain.ContractDiff{
			"contractdiff_test": {ID: "contractdiff_test", TenantID: "ten_test", BaseContractID: "contract_test", TargetContractID: "contract_test", ProductID: "prod_test", ReleaseID: "rel_test", Result: "non_breaking", NonBreakingChanges: []string{"metadata"}, SchemaVersion: domain.ContractDiffSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		CustomPolicies: map[string]domain.CustomPolicy{
			"custom_policy_test": {ID: "custom_policy_test", TenantID: "ten_test", Name: "policy", Version: "1", Description: "test", Rules: []domain.PolicyRule{{Name: "sbom", EvidenceType: "sbom", Severity: "high", Required: true}}, SchemaVersion: domain.CustomPolicySchemaVersion, CreatedAt: time.Now().UTC()},
		},
		CustomPolicyEvaluations: map[string]domain.CustomPolicyEvaluation{
			"custom_policy_eval_test": {ID: "custom_policy_eval_test", TenantID: "ten_test", PolicyID: "custom_policy_test", ReleaseID: "rel_test", Result: "pass", Checks: []domain.PolicyCheck{{Name: "sbom", Result: "passed", Severity: "high"}}, InputHash: "sha256:" + strings.Repeat("e", 64), SchemaVersion: domain.CustomPolicyEvalSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Waivers: map[string]domain.Waiver{
			"waiver_test": {ID: "waiver_test", TenantID: "ten_test", ScopeType: "release", ScopeID: "rel_test", ControlID: "control_test", PolicyID: "custom_policy_test", Owner: "security", Risk: "accepted", Reason: "test", ExpiresAt: time.Now().UTC().Add(24 * time.Hour), Approved: true, ApprovedBy: "user_test", ApprovedAt: ptrTime(time.Now().UTC()), SchemaVersion: domain.WaiverSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Approvals: map[string]domain.ApprovalRecord{
			"approval_test": {ID: "approval_test", TenantID: "ten_test", SubjectType: "release", SubjectID: "rel_test", Decision: "approved", Reason: "test", ApproverID: "user_test", EvidenceID: "ev_test", SchemaVersion: domain.ApprovalRecordSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		DSSETrustRoots: map[string]domain.DSSETrustRoot{
			"dsse_root_test": {ID: "dsse_root_test", TenantID: "ten_test", Name: "root", KeyID: "key-1", Algorithm: "Ed25519", PublicKey: "pub", Status: "active", SchemaVersion: domain.DSSETrustRootSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		CosignVerifications: map[string]domain.CosignVerification{
			"cosign_test": {ID: "cosign_test", TenantID: "ten_test", ArtifactID: "art_test", ContainerImageID: "image_test", ArtifactSignatureID: "artsig_test", SubjectDigest: "sha256:" + strings.Repeat("a", 64), RekorUUID: "rekor", RekorLogIndex: "1", CertificateIdentity: "repo", CertificateIssuer: "issuer", Result: "pass", Checks: []domain.VerifyCheck{{Name: "digest", Result: "passed"}}, SchemaVersion: domain.CosignVerificationSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		SigningProviders: map[string]domain.SigningProvider{
			"sign_provider_test": {ID: "sign_provider_test", TenantID: "ten_test", Name: "kms", Type: "aws_kms", Status: "active", KeyRef: "arn:aws:kms:test", Encrypted: true, SchemaVersion: domain.SigningProviderSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		MerkleBatches: map[string]domain.MerkleBatch{
			"merkle_test": {ID: "merkle_test", TenantID: "ten_test", FromSequence: 1, ToSequence: 1, EntryCount: 1, LeafHashes: []string{"sha256:" + strings.Repeat("e", 64)}, RootHash: "sha256:" + strings.Repeat("f", 64), SignatureRefs: []string{"sig_test"}, SchemaVersion: domain.MerkleBatchSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		TransparencyCheckpoints: map[string]domain.TransparencyCheckpoint{
			"transparency_test": {ID: "transparency_test", TenantID: "ten_test", BatchID: "merkle_test", Provider: "internal", ExternalURL: "https://transparency.example.test", ExternalID: "ts-1", TimestampHash: "sha256:" + strings.Repeat("0", 64), State: "recorded", SchemaVersion: domain.TransparencyCheckpointVersion, CreatedAt: time.Now().UTC()},
		},
		Chain: map[string][]domain.AuditChainEntry{
			"ten_test": {{
				ID: "chain_test", TenantID: "ten_test", Sequence: 1, EntryType: "evidence.created", SubjectType: "evidence_item", SubjectID: "ev_test",
				ActorType: "user", ActorID: "user_test", OccurredAt: time.Now().UTC(), PayloadHash: "sha256:" + strings.Repeat("b", 64),
				CanonicalEntryHash: "sha256:" + strings.Repeat("d", 64), PreviousEntryHash: "", EntryHash: "sha256:" + strings.Repeat("e", 64),
				SchemaVersion: domain.AuditChainEntrySchemaVersion,
			}},
		},
		SigningKeys: map[string]domain.SigningKey{
			"sigkey_test": {ID: "sigkey_test", TenantID: "ten_test", KID: "kid-test", Algorithm: "Ed25519", Status: "active", PublicKey: "public", CreatedAt: time.Now().UTC()},
		},
		SigningKeyPrivate: map[string][]byte{"sigkey_test": []byte("dev-private-key")},
		Signatures: map[string]domain.Signature{
			"sig_test": {ID: "sig_test", TenantID: "ten_test", SubjectType: "release_bundle", SubjectID: "bundle_test", KeyID: "sigkey_test", Algorithm: "Ed25519", Value: "signature", CreatedAt: time.Now().UTC()},
		},
		SBOMs: map[string]domain.SBOM{
			"sbom_test": {ID: "sbom_test", TenantID: "ten_test", EvidenceID: "ev_test", ReleaseID: "rel_test", ArtifactID: "art_test", Format: "cyclonedx", SpecVersion: "1.5", ComponentCount: 1, Components: []domain.SBOMComponent{{Name: "lib", Version: "1.0.0"}}, CreatedAt: time.Now().UTC()},
		},
		Scans: map[string]domain.VulnerabilityScan{
			"scan_test": {ID: "scan_test", TenantID: "ten_test", EvidenceID: "ev_test", ReleaseID: "rel_test", Scanner: "scanner", TargetRef: "artifact.tar.gz", Summary: map[string]int{"critical": 0}, Findings: []domain.VulnerabilityFinding{{ID: "finding_test", Vulnerability: "CVE-0000-0001", Severity: "low", State: "open"}}, CreatedAt: time.Now().UTC()},
		},
		VEXDocuments: map[string]domain.VEXDocument{
			"vex_test": {ID: "vex_test", TenantID: "ten_test", EvidenceID: "ev_test", ReleaseID: "rel_test", ArtifactID: "art_test", Format: "openvex", Author: "tester", Version: "1", StatementCount: 1, StatusSummary: map[string]int{"not_affected": 1}, SchemaVersion: domain.VEXDocumentSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		Decisions: map[string]domain.VulnerabilityDecision{
			"decision_test": {ID: "decision_test", TenantID: "ten_test", FindingID: "finding_test", ScanID: "scan_test", ReleaseID: "rel_test", Vulnerability: "CVE-0000-0001", Component: "lib", Status: "not_affected", Justification: "not_present", Source: "manual", EvidenceID: "ev_test", VEXDocumentID: "vex_test", SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: time.Now().UTC()},
		},
		Contracts: map[string]domain.OpenAPIContract{
			"contract_test": {ID: "contract_test", TenantID: "ten_test", ProductID: "prod_test", ReleaseID: "rel_test", Version: "1.0.0", Hash: "sha256:" + strings.Repeat("f", 64), PathCount: 1, Operations: []domain.OpenAPIOperation{{Path: "/v1/test", Method: "get", OperationID: "getTest"}}, EvidenceID: "ev_test", CreatedAt: time.Now().UTC()},
		},
		Policies: map[string]domain.PolicyEvaluation{
			"policy_test": {ID: "policy_test", TenantID: "ten_test", ReleaseID: "rel_test", Result: "pass", PolicySet: domain.PolicySetVersion, Checks: []domain.PolicyCheck{{Name: "sbom", Result: "passed", Severity: "high", Explanation: "test"}}, CreatedAt: time.Now().UTC()},
		},
		Bundles: map[string]domain.ReleaseBundle{
			"bundle_test": {ID: "bundle_test", TenantID: "ten_test", ReleaseID: "rel_test", State: "generated", Manifest: map[string]any{"release_id": "rel_test"}, ManifestHash: "sha256:" + strings.Repeat("1", 64), SignatureRefs: []string{"sig_test"}, CreatedAt: time.Now().UTC()},
		},
		Verifications: map[string]domain.VerificationResult{
			"verify_test": {ID: "verify_test", TenantID: "ten_test", SubjectType: "release_bundle", SubjectID: "bundle_test", Result: "pass", Checks: []domain.VerifyCheck{{Name: "signature", Result: "passed"}}, VerifiedAt: time.Now().UTC()},
		},
		Exceptions: map[string]domain.Exception{
			"exception_test": {ID: "exception_test", TenantID: "ten_test", ReleaseID: "rel_test", FindingID: "finding_test", Reason: "accepted for test", Owner: "security", ExpiresAt: time.Now().UTC().Add(24 * time.Hour), Approved: true, ApprovedBy: "user_test", ApprovedAt: ptrTime(time.Now().UTC()), CreatedAt: time.Now().UTC()},
		},
		ControlFrameworks: map[string]domain.ControlFramework{
			"framework_test": {ID: "framework_test", TenantID: "ten_test", Name: "Framework", Slug: "framework", Version: "1", Description: "test", Status: "active", SchemaVersion: domain.ControlFrameworkSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		SecurityControls: map[string]domain.SecurityControl{
			"control_test": {ID: "control_test", TenantID: "ten_test", FrameworkID: "framework_test", Code: "EVY-1", Title: "Evidence", Objective: "Collect evidence", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "sbom", Required: true}}, Applicability: []string{"release"}, Limitations: []string{"test"}, SchemaVersion: domain.SecurityControlSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		ControlEvidence: map[string]domain.ControlEvidence{
			"control_evidence_test": {ID: "control_evidence_test", TenantID: "ten_test", ControlID: "control_test", EvidenceType: "sbom", SubjectType: "evidence", SubjectID: "ev_test", ProductID: "prod_test", ReleaseID: "rel_test", Confidence: "high", Notes: "linked", SchemaVersion: domain.ControlEvidenceSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		RedactionProfiles: map[string]domain.RedactionProfile{
			"redact_test": {ID: "redact_test", TenantID: "ten_test", Name: "Default", Description: "profile", AllowedTypes: []string{"sbom"}, ExcludedFields: []string{"metadata.secret"}, SchemaVersion: domain.RedactionProfileSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		CustomerPackages: map[string]domain.CustomerSecurityPackage{
			"pkg_test": {ID: "pkg_test", TenantID: "ten_test", ProductID: "prod_test", ReleaseID: "rel_test", RedactionProfileID: "redact_test", Title: "Package", State: "generated", Manifest: map[string]any{"release_id": "rel_test"}, ManifestHash: "sha256:" + strings.Repeat("2", 64), ExpiresAt: time.Now().UTC().Add(24 * time.Hour), AccessCount: 3, SchemaVersion: domain.CustomerPackageSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		HTMLReports: map[string]domain.HTMLReportPackage{
			"html_test": {ID: "html_test", TenantID: "ten_test", ReportType: "cra_readiness", ProductID: "prod_test", ReleaseID: "rel_test", HTML: "<html></html>", Hash: "sha256:" + strings.Repeat("3", 64), SchemaVersion: "html-report-package.v1.0.0", CreatedAt: time.Now().UTC()},
		},
		ReportTemplates: map[string]domain.CustomReportTemplate{
			"tpl_test": {ID: "tpl_test", TenantID: "ten_test", Name: "report", Version: "1", ReportType: "custom", AllowedFields: []string{"id"}, Template: "{{id}}", SchemaVersion: domain.ReportTemplateSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		RenderedReports: map[string]domain.RenderedCustomReport{
			"render_test": {ID: "render_test", TenantID: "ten_test", TemplateID: "tpl_test", SubjectType: "release", SubjectID: "rel_test", Output: map[string]any{"id": "rel_test"}, Hash: "sha256:" + strings.Repeat("4", 64), SchemaVersion: "rendered-report.v1.0.0", CreatedAt: time.Now().UTC()},
		},
		EvidenceBundles: map[string]domain.EvidenceBundle{
			"eb_test": {ID: "eb_test", TenantID: "ten_test", ReleaseID: "rel_test", EvidenceIDs: []string{"ev_test"}, Manifest: map[string]any{"evidence_ids": []any{"ev_test"}}, ManifestHash: "sha256:" + strings.Repeat("5", 64), SignatureRefs: []string{"sig_test"}, VerificationText: "verify", SchemaVersion: domain.EvidenceBundleSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		BundleImports: map[string]domain.EvidenceBundleImport{
			"ebi_test": {ID: "ebi_test", TenantID: "ten_test", BundleHash: "sha256:" + strings.Repeat("5", 64), Result: "imported", ImportedCount: 1, SchemaVersion: domain.EvidenceBundleImportVersion, CreatedAt: time.Now().UTC()},
		},
		ObjectRetentionPolicies: map[string]domain.ObjectRetentionPolicy{
			"orp_test": {ID: "orp_test", TenantID: "ten_test", Name: "retain", ObjectPrefix: "tenants/ten_test/", Mode: "governance", RetentionDays: 30, Status: "verified", VerifiedAt: ptrTime(time.Now().UTC()), VerificationHash: "sha256:" + strings.Repeat("6", 64), VerificationChecks: []domain.VerifyCheck{{Name: "versioning", Result: "passed"}}, VerificationLimitations: []string{"test"}, SchemaVersion: domain.ObjectRetentionPolicyVersion, CreatedAt: time.Now().UTC()},
		},
		BackupManifests: map[string]domain.BackupManifest{
			"bak_test": {ID: "bak_test", TenantID: "ten_test", StateHash: "sha256:" + strings.Repeat("7", 64), ResourceCounts: map[string]int{"evidence": 1}, ConsistencyChecks: []domain.VerifyCheck{{Name: "chain", Result: "passed"}}, Limitations: []string{"objects separately backed up"}, SchemaVersion: domain.BackupManifestSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		LegalHolds: map[string]domain.LegalHold{
			"hold_test": {ID: "hold_test", TenantID: "ten_test", ScopeType: "release", ScopeID: "rel_test", Reason: "review", Owner: "security", ReleasedAt: ptrTime(time.Now().UTC()), SchemaVersion: domain.LegalHoldSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		RetentionOverrides: map[string]domain.RetentionOverride{
			"ret_test": {ID: "ret_test", TenantID: "ten_test", ScopeType: "release", ScopeID: "rel_test", RetentionUntil: time.Now().UTC().Add(365 * 24 * time.Hour), Reason: "policy", Owner: "security", SchemaVersion: domain.RetentionOverrideSchemaVersion, CreatedAt: time.Now().UTC()},
		},
		QuestionnaireTemplates: map[string]domain.QuestionnaireTemplate{
			"qt_test": {ID: "qt_test", TenantID: "ten_test", Name: "questionnaire", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q1", Prompt: "Evidence?", EvidenceType: "sbom"}}, SchemaVersion: domain.QuestionnaireTemplateVersion, CreatedAt: time.Now().UTC()},
		},
		QuestionnairePackages: map[string]domain.QuestionnairePackage{
			"qp_test": {ID: "qp_test", TenantID: "ten_test", TemplateID: "qt_test", PackageID: "pkg_test", ProductID: "prod_test", ReleaseID: "rel_test", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "See evidence", EvidenceIDs: []string{"ev_test"}}}, ManifestHash: "sha256:" + strings.Repeat("8", 64), SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: time.Now().UTC()},
		},
		CommercialCollectors: map[string]domain.CommercialCollectorDefinition{
			"commercial_collector_test": {ID: "commercial_collector_test", TenantID: "ten_test", Name: "scanner", Provider: "scannerco", Version: "1.0.0", ManifestHash: "sha256:" + strings.Repeat("a", 64), AllowedScopes: []string{"evidence:write"}, Status: "active", SchemaVersion: domain.CommercialCollectorVersion, CreatedAt: time.Now().UTC()},
		},
		EvidenceSummaries: map[string]domain.EvidenceSummary{
			"summary_test": {ID: "summary_test", TenantID: "ten_test", SubjectType: "release", SubjectID: "rel_test", EvidenceIDs: []string{"ev_test"}, Summary: "Evidence summary.", Citations: []domain.EvidenceCitation{{EvidenceID: "ev_test", Type: "sbom", Title: "SBOM", CanonicalHash: "sha256:" + strings.Repeat("c", 64)}}, Assumptions: []string{"stored evidence only"}, Limitations: []string{"not a compliance conclusion"}, SchemaVersion: domain.EvidenceSummaryVersion, CreatedAt: time.Now().UTC()},
		},
		QuestionnaireDrafts: map[string]domain.QuestionnaireDraft{
			"draft_test": {ID: "draft_test", TenantID: "ten_test", TemplateID: "qt_test", ProductID: "prod_test", ReleaseID: "rel_test", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Draft", EvidenceIDs: []string{"ev_test"}}}, ManifestHash: "sha256:" + strings.Repeat("b", 64), Limitations: []string{"draft"}, SchemaVersion: domain.QuestionnaireDraftVersion, CreatedAt: time.Now().UTC()},
		},
		GraphSnapshots: map[string]domain.EvidenceGraphSnapshot{
			"graph_test": {ID: "graph_test", TenantID: "ten_test", ProductID: "prod_test", ReleaseID: "rel_test", Nodes: []domain.GraphNode{{ID: "ev_test", Type: "evidence", Label: "SBOM"}}, Edges: []domain.GraphEdge{{From: "rel_test", To: "ev_test", Relationship: "has_evidence"}}, GraphHash: "sha256:" + strings.Repeat("c", 64), Limitations: []string{"snapshot"}, SchemaVersion: domain.EvidenceGraphSnapshotVersion, CreatedAt: time.Now().UTC()},
		},
		SaaSProfiles: map[string]domain.SaaSEditionProfile{
			"saas_test": {ID: "saas_test", TenantID: "ten_test", Name: "hosted", Region: "eu", AdminTenantID: "ten_test", IsolationModel: "shared-control-plane", Status: "draft", ConfigHash: "sha256:" + strings.Repeat("d", 64), Limitations: []string{"not production"}, SchemaVersion: domain.SaaSEditionProfileVersion, CreatedAt: time.Now().UTC()},
		},
		PublicTransparencyLogs: map[string]domain.PublicTransparencyLog{
			"public_log_test": {ID: "public_log_test", TenantID: "ten_test", Name: "log", Endpoint: "https://log.example.test", PublicKey: "pub", State: "active", SchemaVersion: domain.PublicTransparencyLogVersion, CreatedAt: time.Now().UTC()},
		},
		PublicTransparencyItems: map[string]domain.PublicTransparencyLogEntry{
			"public_entry_test": {ID: "public_entry_test", TenantID: "ten_test", LogID: "public_log_test", CheckpointID: "transparency_test", MerkleBatchID: "merkle_test", ExternalID: "entry-1", EntryHash: "sha256:" + strings.Repeat("e", 64), InclusionRootHash: "sha256:" + strings.Repeat("f", 64), InclusionProofHash: "sha256:" + strings.Repeat("1", 64), InclusionVerifiedAt: ptrTime(time.Now().UTC()), VerificationChecks: []domain.VerifyCheck{{Name: "inclusion", Result: "passed"}}, VerificationLimitations: []string{"operator proof"}, State: "verified", SchemaVersion: domain.PublicTransparencyEntryVersion, CreatedAt: time.Now().UTC()},
		},
		MarketplaceCollectors: map[string]domain.MarketplaceCollector{
			"market_collector_test": {ID: "market_collector_test", TenantID: "ten_test", Name: "scanner", Provider: "scannerco", Version: "1.0.0", Publisher: "scannerco", ManifestHash: "sha256:" + strings.Repeat("a", 64), SignatureID: "artsig_test", SBOMID: "sbom_test", ScanID: "scan_test", State: "published", Limitations: []string{"external distribution"}, SchemaVersion: domain.MarketplaceCollectorVersion, CreatedAt: time.Now().UTC()},
		},
		PDFReports: map[string]domain.PDFReportPackage{
			"pdf_test": {ID: "pdf_test", TenantID: "ten_test", ReportType: "cra_readiness", ProductID: "prod_test", ReleaseID: "rel_test", Title: "PDF", PayloadRef: "object://tenants/ten_test/reports/pdf", PayloadHash: "sha256:" + strings.Repeat("9", 64), PayloadSize: 10, Limitations: []string{"test"}, SchemaVersion: domain.PDFReportPackageVersion, CreatedAt: time.Now().UTC()},
		},
		AnomalyReports: map[string]domain.AnomalyReport{
			"anom_test": {ID: "anom_test", TenantID: "ten_test", SubjectType: "release", SubjectID: "rel_test", Result: "review", Signals: []domain.AnomalySignal{{Name: "gap", Severity: "medium", Detail: "test"}}, Assumptions: []string{"heuristic"}, Limitations: []string{"not ML"}, SchemaVersion: domain.AnomalyReportVersion, CreatedAt: time.Now().UTC()},
		},
		ProviderVerifications: map[string]domain.ProviderVerification{
			"provider_verification_test": {ID: "provider_verification_test", TenantID: "ten_test", ProviderType: "oidc", ProviderID: "sso_test", Subject: "sub", Result: "verified", Checks: []domain.VerifyCheck{{Name: "subject", Result: "passed"}}, Limitations: []string{"static trust material"}, SchemaVersion: domain.ProviderVerificationVersion, CreatedAt: time.Now().UTC()},
		},
		SigningOperations: map[string]domain.SigningOperation{
			"signing_operation_test": {ID: "signing_operation_test", TenantID: "ten_test", ProviderID: "sign_provider_test", SubjectType: "release", SubjectID: "rel_test", PayloadHash: "sha256:" + strings.Repeat("2", 64), SignatureRef: "sig_test", Result: "signed", Checks: []domain.VerifyCheck{{Name: "provider", Result: "passed"}}, SchemaVersion: domain.SigningOperationVersion, CreatedAt: time.Now().UTC()},
		},
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
	if _, err := store.pool.Exec(ctx, `UPDATE products SET name = $1 WHERE tenant_id = 'ten_test' AND id = 'prod_test'`, "Relational Product"); err != nil {
		t.Fatal(err)
	}
	store.loadMode = LoadModeRelationalPreferred
	relationalPreferred, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load relational-preferred state ok=%v err=%v", ok, err)
	}
	if relationalPreferred.Products["prod_test"].Name != "Relational Product" {
		t.Fatalf("relational-preferred product name = %q", relationalPreferred.Products["prod_test"].Name)
	}
	store.loadMode = LoadModeSnapshotPreferred
	snapshotPreferred, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load snapshot-preferred state ok=%v err=%v", ok, err)
	}
	if snapshotPreferred.Products["prod_test"].Name != "Product" {
		t.Fatalf("snapshot-preferred product name = %q", snapshotPreferred.Products["prod_test"].Name)
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
	var portalHash string
	if err := store.pool.QueryRow(ctx, `SELECT hash FROM customer_portal_access WHERE id = 'cpa_test' AND failed_access_count = 1 AND last_accessed_at IS NOT NULL`).Scan(&portalHash); err != nil {
		t.Fatal(err)
	}
	if portalHash != "portal-token-hash" {
		t.Fatalf("portal hash = %q", portalHash)
	}
	coreChecks := []struct {
		name  string
		query string
	}{
		{name: "product", query: `SELECT count(*) FROM products WHERE tenant_id = 'ten_test' AND id = 'prod_test'`},
		{name: "project", query: `SELECT count(*) FROM projects WHERE tenant_id = 'ten_test' AND product_id = 'prod_test'`},
		{name: "release", query: `SELECT count(*) FROM releases WHERE tenant_id = 'ten_test' AND id = 'rel_test'`},
		{name: "artifact", query: `SELECT count(*) FROM artifacts WHERE tenant_id = 'ten_test' AND digest LIKE 'sha256:%'`},
		{name: "collector", query: `SELECT count(*) FROM collectors WHERE tenant_id = 'ten_test' AND id = 'collector_test' AND allowed_scopes <> '[]'::jsonb`},
		{name: "collector release", query: `SELECT count(*) FROM collector_releases WHERE tenant_id = 'ten_test' AND id = 'collector_release_test' AND pinned = true`},
		{name: "build run", query: `SELECT count(*) FROM build_runs WHERE tenant_id = 'ten_test' AND id = 'build_test' AND outputs <> '[]'::jsonb`},
		{name: "build attestation", query: `SELECT count(*) FROM build_attestations WHERE tenant_id = 'ten_test' AND id = 'att_test' AND subject_digests <> '[]'::jsonb`},
		{name: "evidence", query: `SELECT count(*) FROM evidence_items WHERE tenant_id = 'ten_test' AND id = 'ev_test' AND evidence_version = 1 AND product_id = 'prod_test'`},
		{name: "evidence lifecycle", query: `SELECT count(*) FROM evidence_lifecycle_events WHERE tenant_id = 'ten_test' AND id = 'life_test' AND details <> '{}'::jsonb`},
		{name: "release candidate", query: `SELECT count(*) FROM release_candidates WHERE tenant_id = 'ten_test' AND id = 'rc_test' AND document <> '{}'::jsonb`},
		{name: "container image", query: `SELECT count(*) FROM container_images WHERE tenant_id = 'ten_test' AND id = 'image_test'`},
		{name: "artifact signature", query: `SELECT count(*) FROM artifact_signatures WHERE tenant_id = 'ten_test' AND id = 'artsig_test'`},
		{name: "source repository", query: `SELECT count(*) FROM source_repositories WHERE tenant_id = 'ten_test' AND id = 'repo_test'`},
		{name: "source commit", query: `SELECT count(*) FROM source_commits WHERE tenant_id = 'ten_test' AND id = 'commit_test'`},
		{name: "source branch", query: `SELECT count(*) FROM source_branches WHERE tenant_id = 'ten_test' AND id = 'branch_test' AND protected = true`},
		{name: "pull request", query: `SELECT count(*) FROM pull_requests WHERE tenant_id = 'ten_test' AND id = 'pr_test' AND review_decision = 'approved'`},
		{name: "deployment environment", query: `SELECT count(*) FROM deployment_environments WHERE tenant_id = 'ten_test' AND id = 'env_test'`},
		{name: "deployment event", query: `SELECT count(*) FROM deployment_events WHERE tenant_id = 'ten_test' AND id = 'deploy_test' AND artifact_ids = ARRAY['art_test']`},
		{name: "incident", query: `SELECT count(*) FROM incidents WHERE tenant_id = 'ten_test' AND id = 'incident_test' AND status = 'resolved'`},
		{name: "incident timeline", query: `SELECT count(*) FROM incident_timeline_events WHERE tenant_id = 'ten_test' AND id = 'timeline_test' AND evidence_id = 'ev_test'`},
		{name: "incident webhook receiver", query: `SELECT count(*) FROM incident_webhook_receivers WHERE tenant_id = 'ten_test' AND id = 'receiver_test' AND status = 'active'`},
		{name: "incident webhook event", query: `SELECT count(*) FROM incident_webhook_events WHERE tenant_id = 'ten_test' AND id = 'webhook_event_test' AND timeline_event_id = 'timeline_test'`},
		{name: "remediation task", query: `SELECT count(*) FROM remediation_tasks WHERE tenant_id = 'ten_test' AND id = 'remediation_test' AND status = 'done'`},
		{name: "security scan", query: `SELECT count(*) FROM security_scans WHERE tenant_id = 'ten_test' AND id = 'secscan_test' AND summary <> '{}'::jsonb`},
		{name: "manual security doc", query: `SELECT count(*) FROM manual_security_documents WHERE tenant_id = 'ten_test' AND id = 'manual_doc_test' AND sensitivity = 'restricted'`},
		{name: "sbom diff", query: `SELECT count(*) FROM sbom_diffs WHERE tenant_id = 'ten_test' AND id = 'sbomdiff_test' AND document <> '{}'::jsonb`},
		{name: "dependency change", query: `SELECT count(*) FROM dependency_changes WHERE tenant_id = 'ten_test' AND id = 'depchange_test' AND component <> '{}'::jsonb`},
		{name: "vulnerability workflow", query: `SELECT count(*) FROM vulnerability_workflow_records WHERE tenant_id = 'ten_test' AND id = 'vulnwf_test' AND action = 'reopened'`},
		{name: "contract diff", query: `SELECT count(*) FROM contract_diffs WHERE tenant_id = 'ten_test' AND id = 'contractdiff_test' AND document <> '{}'::jsonb`},
		{name: "custom policy", query: `SELECT count(*) FROM custom_policies WHERE tenant_id = 'ten_test' AND id = 'custom_policy_test' AND rules <> '[]'::jsonb`},
		{name: "custom policy evaluation", query: `SELECT count(*) FROM custom_policy_evaluations WHERE tenant_id = 'ten_test' AND id = 'custom_policy_eval_test' AND checks <> '[]'::jsonb`},
		{name: "waiver", query: `SELECT count(*) FROM waivers WHERE tenant_id = 'ten_test' AND id = 'waiver_test' AND approved = true`},
		{name: "approval", query: `SELECT count(*) FROM approval_records WHERE tenant_id = 'ten_test' AND id = 'approval_test' AND evidence_id = 'ev_test'`},
		{name: "dsse trust root", query: `SELECT count(*) FROM dsse_trust_roots WHERE tenant_id = 'ten_test' AND id = 'dsse_root_test' AND status = 'active'`},
		{name: "cosign verification", query: `SELECT count(*) FROM cosign_verifications WHERE tenant_id = 'ten_test' AND id = 'cosign_test' AND checks <> '[]'::jsonb`},
		{name: "signing provider", query: `SELECT count(*) FROM signing_providers WHERE tenant_id = 'ten_test' AND id = 'sign_provider_test' AND encrypted = true`},
		{name: "merkle batch", query: `SELECT count(*) FROM merkle_batches WHERE tenant_id = 'ten_test' AND id = 'merkle_test' AND signature_refs = ARRAY['sig_test']`},
		{name: "transparency checkpoint", query: `SELECT count(*) FROM transparency_checkpoints WHERE tenant_id = 'ten_test' AND id = 'transparency_test' AND external_id = 'ts-1'`},
		{name: "audit chain", query: `SELECT count(*) FROM audit_chain_entries WHERE tenant_id = 'ten_test' AND sequence = 1`},
		{name: "signing key", query: `SELECT count(*) FROM signing_keys WHERE tenant_id = 'ten_test' AND id = 'sigkey_test' AND encrypted_private_key IS NOT NULL`},
		{name: "signature", query: `SELECT count(*) FROM signatures WHERE tenant_id = 'ten_test' AND id = 'sig_test'`},
		{name: "sbom", query: `SELECT count(*) FROM sboms WHERE tenant_id = 'ten_test' AND release_id = 'rel_test' AND component_count = 1`},
		{name: "scan", query: `SELECT count(*) FROM vulnerability_scans WHERE tenant_id = 'ten_test' AND release_id = 'rel_test'`},
		{name: "vex", query: `SELECT count(*) FROM vex_documents WHERE tenant_id = 'ten_test' AND id = 'vex_test' AND statement_count = 1`},
		{name: "decision", query: `SELECT count(*) FROM vulnerability_decisions WHERE tenant_id = 'ten_test' AND id = 'decision_test' AND status = 'not_affected'`},
		{name: "exception", query: `SELECT count(*) FROM exceptions WHERE tenant_id = 'ten_test' AND id = 'exception_test' AND approved = true`},
		{name: "contract", query: `SELECT count(*) FROM openapi_contracts WHERE tenant_id = 'ten_test' AND id = 'contract_test' AND operations <> '[]'::jsonb`},
		{name: "policy", query: `SELECT count(*) FROM policy_evaluations WHERE tenant_id = 'ten_test' AND id = 'policy_test'`},
		{name: "bundle", query: `SELECT count(*) FROM release_bundles WHERE tenant_id = 'ten_test' AND id = 'bundle_test'`},
		{name: "verification", query: `SELECT count(*) FROM verification_results WHERE tenant_id = 'ten_test' AND id = 'verify_test'`},
		{name: "control framework", query: `SELECT count(*) FROM control_frameworks WHERE tenant_id = 'ten_test' AND id = 'framework_test'`},
		{name: "security control", query: `SELECT count(*) FROM security_controls WHERE tenant_id = 'ten_test' AND id = 'control_test' AND evidence_requirements <> '[]'::jsonb`},
		{name: "control evidence", query: `SELECT count(*) FROM control_evidence WHERE tenant_id = 'ten_test' AND id = 'control_evidence_test'`},
		{name: "redaction profile", query: `SELECT count(*) FROM redaction_profiles WHERE tenant_id = 'ten_test' AND id = 'redact_test' AND allowed_types = ARRAY['sbom']`},
		{name: "customer package", query: `SELECT count(*) FROM customer_security_packages WHERE tenant_id = 'ten_test' AND id = 'pkg_test' AND access_count = 3`},
		{name: "html report", query: `SELECT count(*) FROM html_report_packages WHERE tenant_id = 'ten_test' AND id = 'html_test'`},
		{name: "report template", query: `SELECT count(*) FROM report_templates WHERE tenant_id = 'ten_test' AND id = 'tpl_test'`},
		{name: "rendered report", query: `SELECT count(*) FROM rendered_reports WHERE tenant_id = 'ten_test' AND id = 'render_test'`},
		{name: "evidence bundle", query: `SELECT count(*) FROM evidence_bundles WHERE tenant_id = 'ten_test' AND id = 'eb_test'`},
		{name: "evidence bundle import", query: `SELECT count(*) FROM evidence_bundle_imports WHERE tenant_id = 'ten_test' AND id = 'ebi_test'`},
		{name: "object retention", query: `SELECT count(*) FROM object_retention_policies WHERE tenant_id = 'ten_test' AND id = 'orp_test' AND verification_checks <> '[]'::jsonb`},
		{name: "backup manifest", query: `SELECT count(*) FROM backup_manifests WHERE tenant_id = 'ten_test' AND id = 'bak_test'`},
		{name: "legal hold", query: `SELECT count(*) FROM legal_holds WHERE tenant_id = 'ten_test' AND id = 'hold_test' AND released_at IS NOT NULL`},
		{name: "retention override", query: `SELECT count(*) FROM retention_overrides WHERE tenant_id = 'ten_test' AND id = 'ret_test'`},
		{name: "questionnaire template", query: `SELECT count(*) FROM questionnaire_templates WHERE tenant_id = 'ten_test' AND id = 'qt_test'`},
		{name: "questionnaire package", query: `SELECT count(*) FROM questionnaire_packages WHERE tenant_id = 'ten_test' AND id = 'qp_test'`},
		{name: "commercial collector", query: `SELECT count(*) FROM commercial_collectors WHERE tenant_id = 'ten_test' AND id = 'commercial_collector_test' AND allowed_scopes = ARRAY['evidence:write']`},
		{name: "evidence summary", query: `SELECT count(*) FROM evidence_summaries WHERE tenant_id = 'ten_test' AND id = 'summary_test' AND citations <> '[]'::jsonb`},
		{name: "questionnaire draft", query: `SELECT count(*) FROM questionnaire_drafts WHERE tenant_id = 'ten_test' AND id = 'draft_test' AND responses <> '[]'::jsonb`},
		{name: "graph snapshot", query: `SELECT count(*) FROM evidence_graph_snapshots WHERE tenant_id = 'ten_test' AND id = 'graph_test' AND nodes <> '[]'::jsonb`},
		{name: "saas profile", query: `SELECT count(*) FROM saas_edition_profiles WHERE tenant_id = 'ten_test' AND id = 'saas_test' AND status = 'draft'`},
		{name: "public transparency log", query: `SELECT count(*) FROM public_transparency_logs WHERE tenant_id = 'ten_test' AND id = 'public_log_test' AND state = 'active'`},
		{name: "public transparency entry", query: `SELECT count(*) FROM public_transparency_log_entries WHERE tenant_id = 'ten_test' AND id = 'public_entry_test' AND inclusion_verified_at IS NOT NULL AND verification_checks <> '[]'::jsonb`},
		{name: "marketplace collector", query: `SELECT count(*) FROM marketplace_collectors WHERE tenant_id = 'ten_test' AND id = 'market_collector_test' AND state = 'published'`},
		{name: "pdf report", query: `SELECT count(*) FROM pdf_report_packages WHERE tenant_id = 'ten_test' AND id = 'pdf_test'`},
		{name: "anomaly report", query: `SELECT count(*) FROM anomaly_reports WHERE tenant_id = 'ten_test' AND id = 'anom_test'`},
		{name: "provider verification", query: `SELECT count(*) FROM provider_verifications WHERE tenant_id = 'ten_test' AND id = 'provider_verification_test' AND checks <> '[]'::jsonb`},
		{name: "signing operation", query: `SELECT count(*) FROM signing_operations WHERE tenant_id = 'ten_test' AND id = 'signing_operation_test' AND signature_ref = 'sig_test'`},
	}
	for _, check := range coreChecks {
		var rows int
		if err := store.pool.QueryRow(ctx, check.query).Scan(&rows); err != nil {
			t.Fatalf("%s relational row query: %v", check.name, err)
		}
		if rows != 1 {
			t.Fatalf("%s relational rows = %d, want 1", check.name, rows)
		}
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM ledger_state WHERE id = 'default'`); err != nil {
		t.Fatal(err)
	}
	relational, ok, err := store.LoadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected relational state fallback after removing snapshot")
	}
	if relational.APIKeyHashes["key_test"] != "hmac-test-hash" {
		t.Fatalf("relational api key hash = %q", relational.APIKeyHashes["key_test"])
	}
	if relational.Organizations["org_test"].Slug != "org" || relational.Users["user_test"].OrganizationID != "org_test" || relational.RoleBindings["rb_test"].Role != "security_engineer" {
		t.Fatalf("relational identity rows missing: org=%#v user=%#v role=%#v", relational.Organizations["org_test"], relational.Users["user_test"], relational.RoleBindings["rb_test"])
	}
	if relational.SSOProviders["sso_test"].TrustMaterialUpdatedAt == nil || len(relational.SSOProviders["sso_test"].JWKS) == 0 || !relational.IdentityLinks["link_test"].Verified {
		t.Fatalf("relational sso rows missing: provider=%#v link=%#v", relational.SSOProviders["sso_test"], relational.IdentityLinks["link_test"])
	}
	if relational.SSOSessionHashes["sess_test"] != "session-hash" || relational.SSOSessions["sess_test"].Prefix != "sess" || len(relational.SSOSessions["sess_test"].Groups) != 1 || relational.SSOSessions["sess_test"].Groups[0] != "security" {
		t.Fatalf("relational sso session = %#v hash=%q", relational.SSOSessions["sess_test"], relational.SSOSessionHashes["sess_test"])
	}
	if relational.Collectors["collector_test"].APIKeyID != "key_test" || relational.BuildRuns["build_test"].Status != "passed" || len(relational.BuildAttestations["att_test"].SubjectDigests) != 1 {
		t.Fatalf("relational build rows missing: collector=%#v build=%#v attestation=%#v", relational.Collectors["collector_test"], relational.BuildRuns["build_test"], relational.BuildAttestations["att_test"])
	}
	if !relational.CollectorReleases["collector_release_test"].Pinned || relational.CollectorReleases["collector_release_test"].HealthStatus != "healthy" {
		t.Fatalf("relational collector release missing: release=%#v", relational.CollectorReleases["collector_release_test"])
	}
	if relational.EvidenceLifecycle["life_test"].Details["field"] != "metadata" || len(relational.ReleaseCandidates["rc_test"].BuildIDs) != 1 {
		t.Fatalf("relational lifecycle/candidate rows missing: lifecycle=%#v candidate=%#v", relational.EvidenceLifecycle["life_test"], relational.ReleaseCandidates["rc_test"])
	}
	if relational.ContainerImages["image_test"].Repository == "" || relational.ArtifactSignatures["artsig_test"].VerificationStatus != "verified" {
		t.Fatalf("relational artifact image rows missing: image=%#v signature=%#v", relational.ContainerImages["image_test"], relational.ArtifactSignatures["artsig_test"])
	}
	if relational.Repositories["repo_test"].FullName != "org/repo" || relational.Commits["commit_test"].SHA == "" || !relational.Branches["branch_test"].Protected || relational.PullRequests["pr_test"].ReviewDecision != "approved" {
		t.Fatalf("relational source rows missing: repo=%#v commit=%#v branch=%#v pr=%#v", relational.Repositories["repo_test"], relational.Commits["commit_test"], relational.Branches["branch_test"], relational.PullRequests["pr_test"])
	}
	if relational.Environments["env_test"].Name != "production" || relational.Deployments["deploy_test"].Status != "succeeded" {
		t.Fatalf("relational deployment rows missing: env=%#v deployment=%#v", relational.Environments["env_test"], relational.Deployments["deploy_test"])
	}
	if relational.Incidents["incident_test"].Status != "resolved" || relational.TimelineEvents["timeline_test"].EvidenceID != "ev_test" {
		t.Fatalf("relational incident rows missing: incident=%#v timeline=%#v", relational.Incidents["incident_test"], relational.TimelineEvents["timeline_test"])
	}
	if relational.IncidentWebhookReceivers["receiver_test"].Status != "active" || relational.IncidentWebhookEvents["webhook_event_test"].TimelineEventID != "timeline_test" {
		t.Fatalf("relational incident webhook rows missing: receiver=%#v event=%#v", relational.IncidentWebhookReceivers["receiver_test"], relational.IncidentWebhookEvents["webhook_event_test"])
	}
	if relational.RemediationTasks["remediation_test"].Status != "done" {
		t.Fatalf("relational remediation task missing: task=%#v", relational.RemediationTasks["remediation_test"])
	}
	if relational.SecurityScans["secscan_test"].Summary["high"] != 1 || relational.ManualSecurityDocs["manual_doc_test"].Sensitivity != "restricted" {
		t.Fatalf("relational security evidence rows missing: scan=%#v doc=%#v", relational.SecurityScans["secscan_test"], relational.ManualSecurityDocs["manual_doc_test"])
	}
	if len(relational.SBOMDiffs["sbomdiff_test"].AddedComponents) != 1 || relational.DependencyChanges["depchange_test"].Component.Name != "lib2" {
		t.Fatalf("relational sbom diff rows missing: diff=%#v change=%#v", relational.SBOMDiffs["sbomdiff_test"], relational.DependencyChanges["depchange_test"])
	}
	if relational.VulnerabilityWorkflow["vulnwf_test"].Action != "reopened" || relational.ContractDiffs["contractdiff_test"].Result != "non_breaking" {
		t.Fatalf("relational workflow/diff rows missing: workflow=%#v diff=%#v", relational.VulnerabilityWorkflow["vulnwf_test"], relational.ContractDiffs["contractdiff_test"])
	}
	if len(relational.CustomPolicies["custom_policy_test"].Rules) != 1 || relational.CustomPolicyEvaluations["custom_policy_eval_test"].Result != "pass" {
		t.Fatalf("relational custom policy rows missing: policy=%#v eval=%#v", relational.CustomPolicies["custom_policy_test"], relational.CustomPolicyEvaluations["custom_policy_eval_test"])
	}
	if !relational.Waivers["waiver_test"].Approved || relational.Approvals["approval_test"].EvidenceID != "ev_test" || relational.DSSETrustRoots["dsse_root_test"].Status != "active" {
		t.Fatalf("relational governance/trust rows missing: waiver=%#v approval=%#v trust=%#v", relational.Waivers["waiver_test"], relational.Approvals["approval_test"], relational.DSSETrustRoots["dsse_root_test"])
	}
	if len(relational.CosignVerifications["cosign_test"].Checks) != 1 || !relational.SigningProviders["sign_provider_test"].Encrypted {
		t.Fatalf("relational signing provider rows missing: cosign=%#v provider=%#v", relational.CosignVerifications["cosign_test"], relational.SigningProviders["sign_provider_test"])
	}
	if relational.MerkleBatches["merkle_test"].RootHash == "" || relational.TransparencyCheckpoints["transparency_test"].ExternalID != "ts-1" {
		t.Fatalf("relational integrity checkpoint rows missing: batch=%#v checkpoint=%#v", relational.MerkleBatches["merkle_test"], relational.TransparencyCheckpoints["transparency_test"])
	}
	if relational.Products["prod_test"].Slug != "product" || relational.Evidence["ev_test"].ReleaseID != "rel_test" || relational.SBOMs["sbom_test"].ComponentCount != 1 {
		t.Fatalf("relational fallback missing core rows: product=%#v evidence=%#v sbom=%#v", relational.Products["prod_test"], relational.Evidence["ev_test"], relational.SBOMs["sbom_test"])
	}
	if relational.VEXDocuments["vex_test"].StatusSummary["not_affected"] != 1 || relational.Decisions["decision_test"].Status != "not_affected" || !relational.Exceptions["exception_test"].Approved {
		t.Fatalf("relational risk rows missing: vex=%#v decision=%#v exception=%#v", relational.VEXDocuments["vex_test"], relational.Decisions["decision_test"], relational.Exceptions["exception_test"])
	}
	if relational.ControlFrameworks["framework_test"].Slug != "framework" || len(relational.SecurityControls["control_test"].EvidenceRequirements) != 1 || relational.ControlEvidence["control_evidence_test"].Confidence != "high" {
		t.Fatalf("relational control rows missing: framework=%#v control=%#v evidence=%#v", relational.ControlFrameworks["framework_test"], relational.SecurityControls["control_test"], relational.ControlEvidence["control_evidence_test"])
	}
	if relational.Contracts["contract_test"].PathCount != 1 || len(relational.Contracts["contract_test"].Operations) != 1 {
		t.Fatalf("relational fallback contract = %#v", relational.Contracts["contract_test"])
	}
	if len(relational.Chain["ten_test"]) != 1 || relational.Bundles["bundle_test"].ManifestHash == "" || relational.Verifications["verify_test"].Result != "pass" {
		t.Fatalf("relational fallback integrity rows missing: chain=%#v bundle=%#v verification=%#v", relational.Chain["ten_test"], relational.Bundles["bundle_test"], relational.Verifications["verify_test"])
	}
	if len(relational.SigningKeyPrivate["sigkey_test"]) == 0 {
		t.Fatal("relational fallback missing local dev signing key bytes")
	}
	if len(relational.Idempotency) != 1 {
		t.Fatalf("relational idempotency records = %d, want 1", len(relational.Idempotency))
	}
	if relational.CustomerPortalHashes["cpa_test"] != "portal-token-hash" || relational.CustomerPortalAccess["cpa_test"].FailedAccessCount != 1 {
		t.Fatalf("relational portal access = %#v hash=%q", relational.CustomerPortalAccess["cpa_test"], relational.CustomerPortalHashes["cpa_test"])
	}
	if relational.RedactionProfiles["redact_test"].Name != "Default" || relational.CustomerPackages["pkg_test"].AccessCount != 3 {
		t.Fatalf("relational package rows missing: redaction=%#v package=%#v", relational.RedactionProfiles["redact_test"], relational.CustomerPackages["pkg_test"])
	}
	if relational.HTMLReports["html_test"].Hash == "" || relational.ReportTemplates["tpl_test"].Template == "" || relational.RenderedReports["render_test"].Hash == "" {
		t.Fatalf("relational report rows missing: html=%#v template=%#v rendered=%#v", relational.HTMLReports["html_test"], relational.ReportTemplates["tpl_test"], relational.RenderedReports["render_test"])
	}
	if relational.EvidenceBundles["eb_test"].ManifestHash == "" || relational.BundleImports["ebi_test"].ImportedCount != 1 {
		t.Fatalf("relational evidence bundle rows missing: bundle=%#v import=%#v", relational.EvidenceBundles["eb_test"], relational.BundleImports["ebi_test"])
	}
	if relational.ObjectRetentionPolicies["orp_test"].Status != "verified" || len(relational.ObjectRetentionPolicies["orp_test"].VerificationChecks) != 1 {
		t.Fatalf("relational object retention policy = %#v", relational.ObjectRetentionPolicies["orp_test"])
	}
	if relational.BackupManifests["bak_test"].ResourceCounts["evidence"] != 1 || relational.LegalHolds["hold_test"].ReleasedAt == nil || relational.RetentionOverrides["ret_test"].Owner != "security" {
		t.Fatalf("relational retention rows missing: backup=%#v hold=%#v override=%#v", relational.BackupManifests["bak_test"], relational.LegalHolds["hold_test"], relational.RetentionOverrides["ret_test"])
	}
	if len(relational.QuestionnaireTemplates["qt_test"].Questions) != 1 || len(relational.QuestionnairePackages["qp_test"].Responses) != 1 {
		t.Fatalf("relational questionnaire rows missing: template=%#v package=%#v", relational.QuestionnaireTemplates["qt_test"], relational.QuestionnairePackages["qp_test"])
	}
	if relational.CommercialCollectors["commercial_collector_test"].Status != "active" || len(relational.EvidenceSummaries["summary_test"].Citations) != 1 {
		t.Fatalf("relational commercial/summary rows missing: collector=%#v summary=%#v", relational.CommercialCollectors["commercial_collector_test"], relational.EvidenceSummaries["summary_test"])
	}
	if len(relational.QuestionnaireDrafts["draft_test"].Responses) != 1 || len(relational.GraphSnapshots["graph_test"].Nodes) != 1 {
		t.Fatalf("relational draft/graph rows missing: draft=%#v graph=%#v", relational.QuestionnaireDrafts["draft_test"], relational.GraphSnapshots["graph_test"])
	}
	if relational.SaaSProfiles["saas_test"].Status != "draft" || relational.PublicTransparencyLogs["public_log_test"].State != "active" {
		t.Fatalf("relational saas/public log rows missing: saas=%#v log=%#v", relational.SaaSProfiles["saas_test"], relational.PublicTransparencyLogs["public_log_test"])
	}
	if relational.PublicTransparencyItems["public_entry_test"].InclusionVerifiedAt == nil || len(relational.PublicTransparencyItems["public_entry_test"].VerificationChecks) != 1 {
		t.Fatalf("relational public transparency entry missing: entry=%#v", relational.PublicTransparencyItems["public_entry_test"])
	}
	if relational.MarketplaceCollectors["market_collector_test"].State != "published" || relational.ProviderVerifications["provider_verification_test"].Result != "verified" {
		t.Fatalf("relational marketplace/provider rows missing: market=%#v provider=%#v", relational.MarketplaceCollectors["market_collector_test"], relational.ProviderVerifications["provider_verification_test"])
	}
	if relational.SigningOperations["signing_operation_test"].SignatureRef != "sig_test" || len(relational.SigningOperations["signing_operation_test"].Checks) != 1 {
		t.Fatalf("relational signing operation missing: operation=%#v", relational.SigningOperations["signing_operation_test"])
	}
	if relational.PDFReports["pdf_test"].PayloadHash == "" || relational.AnomalyReports["anom_test"].Result != "review" {
		t.Fatalf("relational generated report rows missing: pdf=%#v anomaly=%#v", relational.PDFReports["pdf_test"], relational.AnomalyReports["anom_test"])
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
