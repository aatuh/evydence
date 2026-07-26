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
	apiKey := domain.APIKey{ID: "key_repository", TenantID: tenant.ID, Name: "repository key", Prefix: "evy_repo", Hash: "hmac-hash", Scopes: []string{"*"}, CreatedAt: now}
	if err := repositories.Identity.InsertAPIKey(ctx, apiKey); err != nil {
		t.Fatalf("insert API key: %v", err)
	}
	apiKey.LastUsedAt = &now
	if err := repositories.Identity.UpdateAPIKeyLastUsed(ctx, apiKey); err != nil {
		t.Fatalf("update API key last used: %v", err)
	}
	collector := domain.Collector{ID: "col_repository", TenantID: tenant.ID, Name: "Repository collector", Type: "ci", Version: "1.0.0", APIKeyID: apiKey.ID, Status: "active", AllowedScopes: []string{"*"}, SchemaVersion: domain.CollectorSchemaVersion, CreatedAt: now}
	if err := repositories.Builds.InsertCollector(ctx, collector); err != nil {
		t.Fatalf("insert collector: %v", err)
	}
	collector.LastSeenAt = &now
	if err := repositories.Identity.UpdateCollectorLastSeen(ctx, collector); err != nil {
		t.Fatalf("update collector last seen: %v", err)
	}
	if err := repositories.Builds.InsertCollectorRelease(ctx, domain.CollectorRelease{ID: "colrel_repository", TenantID: tenant.ID, CollectorID: collector.ID, Version: "1.0.0", ArtifactDigest: "sha256:collector-release", Pinned: true, VerificationStatus: "recorded", HealthStatus: "needs_evidence", SchemaVersion: domain.CollectorReleaseSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert collector release: %v", err)
	}
	framework := domain.ControlFramework{ID: "fw_repository", TenantID: tenant.ID, Name: "Repository controls", Slug: "repository-controls", Version: "1", Status: "active", SchemaVersion: domain.ControlFrameworkSchemaVersion, CreatedAt: now}
	if err := repositories.Controls.InsertControlFramework(ctx, framework); err != nil {
		t.Fatalf("insert control framework: %v", err)
	}
	control := domain.SecurityControl{ID: "ctrl_repository", TenantID: tenant.ID, FrameworkID: framework.ID, Code: "CTRL-1", Title: "Repository control", Objective: "Record evidence", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "sbom", Required: true}}, SchemaVersion: domain.SecurityControlSchemaVersion, CreatedAt: now}
	if err := repositories.Controls.InsertSecurityControl(ctx, control); err != nil {
		t.Fatalf("insert security control: %v", err)
	}
	organization := domain.Organization{ID: "org_repository", TenantID: tenant.ID, Name: "Repository organization", Slug: "repository-org", Status: "active", SchemaVersion: domain.OrganizationSchemaVersion, CreatedAt: now}
	if err := repositories.Identity.InsertOrganization(ctx, organization); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	user := domain.HumanUser{ID: "usr_repository", TenantID: tenant.ID, OrganizationID: organization.ID, Email: "repository@example.test", DisplayName: "Repository user", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: now}
	if err := repositories.Identity.InsertHumanUser(ctx, user); err != nil {
		t.Fatalf("insert human user: %v", err)
	}
	provider := domain.SSOProvider{ID: "sso_repository", TenantID: tenant.ID, Name: "Repository OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "repository-client", RoleMapping: map[string]string{"security": "security_engineer"}, JWKS: map[string]any{"keys": []any{}}, Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: now}
	if err := repositories.Identity.InsertSSOProvider(ctx, provider); err != nil {
		t.Fatalf("insert SSO provider: %v", err)
	}
	provider.JWKS = map[string]any{"keys": []any{map[string]any{"kid": "repository-key"}}}
	provider.TrustMaterialUpdatedAt = &now
	if err := repositories.Identity.UpdateSSOProviderTrustMaterial(ctx, provider); err != nil {
		t.Fatalf("update SSO provider trust material: %v", err)
	}
	if err := repositories.Identity.InsertRoleBinding(ctx, domain.RoleBinding{ID: "rbac_repository", TenantID: tenant.ID, SubjectType: "user", SubjectID: user.ID, Role: "security_engineer", ResourceType: "tenant", ResourceID: tenant.ID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert role binding: %v", err)
	}
	if err := repositories.Identity.InsertUserIdentityLink(ctx, domain.UserIdentityLink{ID: "link_repository", TenantID: tenant.ID, UserID: user.ID, ProviderID: provider.ID, Subject: "repository-subject", Email: user.Email, Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: now}); err != nil {
		t.Fatalf("insert identity link: %v", err)
	}
	if err := repositories.Identity.InsertProviderVerification(ctx, domain.ProviderVerification{ID: "pvr_repository", TenantID: tenant.ID, ProviderType: provider.Type, ProviderID: provider.ID, Subject: "repository-subject", Result: "passed", Checks: []domain.VerifyCheck{{Name: "signature", Result: "passed"}}, Profile: domain.VerificationProfile{ID: "repository-provider-profile", Version: domain.VerificationProfileSchemaVersion, RequiredChecks: []string{"signature"}, Limitations: []string{"repository test"}}, SchemaVersion: domain.ProviderVerificationVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert provider verification: %v", err)
	}
	var profileID string
	if err := tx.QueryRow(ctx, `SELECT assurance_profile ->> 'id' FROM provider_verifications WHERE id = 'pvr_repository' AND tenant_id = $1`, tenant.ID).Scan(&profileID); err != nil {
		t.Fatalf("read provider verification assurance profile: %v", err)
	}
	if profileID != "repository-provider-profile" {
		t.Fatalf("provider verification assurance profile = %q, want repository-provider-profile", profileID)
	}
	if err := repositories.Identity.InsertProviderVerification(ctx, domain.ProviderVerification{ID: "pvr_repository_wrong_type", TenantID: tenant.ID, ProviderType: "saml", ProviderID: provider.ID, Subject: "repository-subject", Result: "passed", Checks: []domain.VerifyCheck{{Name: "signature", Result: "passed"}}, SchemaVersion: domain.ProviderVerificationVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("provider verification type mismatch err=%v, want not found", err)
	}
	commercial := domain.CommercialCollectorDefinition{ID: "commercial_repository", TenantID: tenant.ID, Name: "Repository collector", Provider: "scanner", Version: "1.0.0", ManifestHash: "sha256:" + strings.Repeat("c", 64), AllowedScopes: []string{app.ScopeEvidenceWrite}, Status: "available", SchemaVersion: domain.CommercialCollectorVersion, CreatedAt: now}
	if err := repositories.Enterprise.InsertCommercialCollectorDefinition(ctx, commercial); err != nil {
		t.Fatalf("insert commercial collector: %v", err)
	}
	session := domain.SSOSession{ID: "sess_repository", TenantID: tenant.ID, UserID: user.ID, ProviderID: provider.ID, Prefix: "evysso_repo", Hash: "session-hash", Groups: []string{"security"}, ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: now}
	if err := repositories.Identity.InsertSSOSession(ctx, session); err != nil {
		t.Fatalf("insert SSO session: %v", err)
	}
	if err := repositories.Identity.ValidateActiveSSOSession(ctx, session, now); err != nil {
		t.Fatalf("validate active SSO session: %v", err)
	}
	product := domain.Product{ID: "prod_repository", TenantID: tenant.ID, Name: "Repository API", Slug: "repository-api", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	if err := repositories.Deployments.InsertDeploymentEnvironment(ctx, domain.DeploymentEnvironment{ID: "env_repository", TenantID: tenant.ID, ProductID: product.ID, Name: "production", Kind: "production", SchemaVersion: domain.DeploymentEnvironmentVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert deployment environment: %v", err)
	}
	project := domain.Project{ID: "proj_repository", TenantID: tenant.ID, ProductID: product.ID, Name: "Repository project", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertProject(ctx, project); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	sourceRepository := domain.SourceRepository{ID: "repo_repository", TenantID: tenant.ID, ProjectID: project.ID, Provider: "github", FullName: "example/repository", SchemaVersion: domain.SourceRepositorySchemaVersion, CreatedAt: now}
	if err := repositories.Source.InsertSourceRepository(ctx, sourceRepository); err != nil {
		t.Fatalf("insert source repository: %v", err)
	}
	sourceCommit := domain.SourceCommit{ID: "commit_repository", TenantID: tenant.ID, RepositoryID: sourceRepository.ID, SHA: "0123456789abcdef0123456789abcdef01234567", CommittedAt: now, SchemaVersion: domain.SourceCommitSchemaVersion, CreatedAt: now}
	if err := repositories.Source.InsertSourceCommit(ctx, sourceCommit); err != nil {
		t.Fatalf("insert source commit: %v", err)
	}
	branch := domain.SourceBranch{ID: "branch_repository", TenantID: tenant.ID, RepositoryID: sourceRepository.ID, Name: "main", HeadCommitID: sourceCommit.ID, Protected: true, SchemaVersion: domain.SourceBranchSchemaVersion, CreatedAt: now}
	if err := repositories.Source.InsertSourceBranch(ctx, branch); err != nil {
		t.Fatalf("insert source branch: %v", err)
	}
	branch.Protected = false
	branch.ProtectionHash = "sha256:branch"
	if err := repositories.Source.UpdateSourceBranch(ctx, branch); err != nil {
		t.Fatalf("update source branch: %v", err)
	}
	if err := repositories.Source.InsertPullRequest(ctx, domain.PullRequest{ID: "pr_repository", TenantID: tenant.ID, RepositoryID: sourceRepository.ID, Provider: "github", ProviderID: "17", Title: "Repository change", State: "merged", HeadCommitID: sourceCommit.ID, SchemaVersion: domain.PullRequestSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert pull request: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO customer_security_packages (
			id, tenant_id, product_id, redaction_profile_id, title, state, manifest,
			manifest_hash, expires_at, schema_version, created_at
		)
		VALUES ('pkg_repository', $1, $2, 'redaction_repository', 'Repository package', 'generated', '{}'::jsonb, 'sha256:package', $3, $4, $5)
	`, tenant.ID, product.ID, now.Add(time.Hour), domain.CustomerPackageSchemaVersion, now); err != nil {
		t.Fatalf("seed customer package: %v", err)
	}
	portalAccess := domain.CustomerPortalAccess{ID: "cpa_repository", TenantID: tenant.ID, PackageID: "pkg_repository", CustomerName: "Repository customer", Prefix: "evycp_repo", Hash: "portal-hash", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.CustomerPortalAccessVersion, CreatedAt: now}
	if err := repositories.Identity.InsertCustomerPortalAccess(ctx, portalAccess); err != nil {
		t.Fatalf("insert customer portal access: %v", err)
	}
	updatedPortalAccess := portalAccess
	updatedPortalAccess.AccessCount = 1
	updatedPortalAccess.LastAccessedAt = &now
	if err := repositories.Identity.UpdateCustomerPortalAccess(ctx, portalAccess, updatedPortalAccess); err != nil {
		t.Fatalf("update customer portal access: %v", err)
	}
	revokedAt := now
	session.RevokedAt = &revokedAt
	if err := repositories.Identity.RevokeSSOSession(ctx, session); err != nil {
		t.Fatalf("revoke SSO session: %v", err)
	}
	if err := repositories.Identity.ValidateActiveSSOSession(ctx, session, now); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatalf("validate revoked SSO session err=%v, want unauthorized", err)
	}
	deactivatedAt := now
	user.Status = "deactivated"
	user.DeactivatedAt = &deactivatedAt
	if err := repositories.Identity.DeactivateHumanUser(ctx, user); err != nil {
		t.Fatalf("deactivate human user: %v", err)
	}
	release := domain.Release{ID: "rel_repository", TenantID: tenant.ID, ProductID: product.ID, Version: "1.0.0", State: "draft", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertRelease(ctx, release); err != nil {
		t.Fatalf("insert release: %v", err)
	}
	release.State = "frozen"
	release.FrozenAt = &now
	if err := repositories.ReleaseCatalog.UpdateReleaseState(ctx, release, "draft"); err != nil {
		t.Fatalf("update release state: %v", err)
	}
	artifact := domain.Artifact{ID: "art_repository", TenantID: tenant.ID, Name: "repository.tgz", MediaType: "application/gzip", Digest: "sha256:repository", Size: 7, CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertArtifact(ctx, artifact); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}
	if err := repositories.SupplyChain.InsertContainerImage(ctx, domain.ContainerImage{ID: "img_repository", TenantID: tenant.ID, ArtifactID: artifact.ID, Repository: "registry.example.test/repository", Digest: artifact.Digest, SchemaVersion: domain.ContainerImageSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert container image: %v", err)
	}
	if err := repositories.SupplyChain.InsertArtifactSignature(ctx, domain.ArtifactSignature{ID: "artsig_repository_port", TenantID: tenant.ID, ArtifactID: artifact.ID, SubjectDigest: artifact.Digest, Algorithm: "cosign", Signature: "signature", VerificationStatus: "recorded", SchemaVersion: domain.ArtifactSignatureSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert artifact signature: %v", err)
	}
	if err := repositories.SupplyChain.InsertContainerImage(ctx, domain.ContainerImage{ID: "img_repository_bad_digest", TenantID: tenant.ID, ArtifactID: artifact.ID, Repository: "registry.example.test/repository-bad", Digest: "sha256:wrong", SchemaVersion: domain.ContainerImageSchemaVersion, CreatedAt: now}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("mismatched image digest err=%v, want validation", err)
	}
	if err := repositories.SupplyChain.InsertArtifactSignature(ctx, domain.ArtifactSignature{ID: "artsig_repository_bad_digest", TenantID: tenant.ID, ArtifactID: artifact.ID, SubjectDigest: "sha256:wrong", Algorithm: "cosign", Signature: "signature", VerificationStatus: "recorded", SchemaVersion: domain.ArtifactSignatureSchemaVersion, CreatedAt: now}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("mismatched signature digest err=%v, want validation", err)
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
	deploymentEvidence := evidence
	deploymentEvidence.ID = "evi_repository_deployment"
	deploymentEvidence.DeploymentID = "dep_repository"
	deploymentEvidence.PayloadHash = "sha256:deployment-payload"
	deploymentEvidence.CanonicalHash = "sha256:deployment-canonical"
	if err := repositories.Evidence.InsertEvidence(ctx, deploymentEvidence); err != nil {
		t.Fatalf("insert deployment evidence: %v", err)
	}
	if err := repositories.Deployments.InsertDeploymentEvent(ctx, domain.DeploymentEvent{ID: "dep_repository", TenantID: tenant.ID, EnvironmentID: "env_repository", ReleaseID: release.ID, ArtifactIDs: []string{artifact.ID}, Status: "succeeded", StartedAt: now, EvidenceID: deploymentEvidence.ID, SchemaVersion: domain.DeploymentEventSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert deployment event: %v", err)
	}
	if err := repositories.Deployments.InsertDeploymentEvent(ctx, domain.DeploymentEvent{ID: "dep_repository_missing_env", TenantID: tenant.ID, EnvironmentID: "env_missing", ReleaseID: release.ID, Status: "succeeded", StartedAt: now, EvidenceID: deploymentEvidence.ID, SchemaVersion: domain.DeploymentEventSchemaVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing deployment environment err=%v, want not found", err)
	}
	if err := repositories.Deployments.InsertDeploymentEvent(ctx, domain.DeploymentEvent{ID: "dep_repository_missing_evidence", TenantID: tenant.ID, EnvironmentID: "env_repository", ReleaseID: release.ID, Status: "succeeded", StartedAt: now, EvidenceID: "evi_missing", SchemaVersion: domain.DeploymentEventSchemaVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing deployment evidence err=%v, want not found", err)
	}
	missingArtifactEvidence := deploymentEvidence
	missingArtifactEvidence.ID = "evi_repository_missing_artifact"
	missingArtifactEvidence.DeploymentID = "dep_repository_missing_artifact"
	if err := repositories.Evidence.InsertEvidence(ctx, missingArtifactEvidence); err != nil {
		t.Fatalf("insert missing-artifact deployment evidence: %v", err)
	}
	if err := repositories.Deployments.InsertDeploymentEvent(ctx, domain.DeploymentEvent{ID: "dep_repository_missing_artifact", TenantID: tenant.ID, EnvironmentID: "env_repository", ReleaseID: release.ID, ArtifactIDs: []string{"art_missing"}, Status: "succeeded", StartedAt: now, EvidenceID: missingArtifactEvidence.ID, SchemaVersion: domain.DeploymentEventSchemaVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing deployment artifact err=%v, want not found", err)
	}
	rollbackEvidence := deploymentEvidence
	rollbackEvidence.ID = "evi_repository_missing_rollback"
	rollbackEvidence.DeploymentID = "dep_repository_missing_rollback"
	if err := repositories.Evidence.InsertEvidence(ctx, rollbackEvidence); err != nil {
		t.Fatalf("insert rollback deployment evidence: %v", err)
	}
	if err := repositories.Deployments.InsertDeploymentEvent(ctx, domain.DeploymentEvent{ID: "dep_repository_missing_rollback", TenantID: tenant.ID, EnvironmentID: "env_repository", ReleaseID: release.ID, Status: "rolled_back", StartedAt: now, EvidenceID: rollbackEvidence.ID, RollbackOf: "dep_missing", SchemaVersion: domain.DeploymentEventSchemaVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing rollback deployment err=%v, want not found", err)
	}
	if err := repositories.Builds.InsertBuildRun(ctx, domain.BuildRun{ID: "build_repository", TenantID: tenant.ID, ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: now, Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}, SourceIdentity: map[string]any{"source": "repository-test"}, SchemaVersion: domain.BuildRunSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert build run: %v", err)
	}
	attestationEvidence := evidence
	attestationEvidence.ID = "evi_repository_attestation"
	attestationEvidence.BuildID = "build_repository"
	attestationEvidence.PayloadHash = "sha256:attestation-payload"
	attestationEvidence.CanonicalHash = "sha256:attestation-canonical"
	if err := repositories.Evidence.InsertEvidence(ctx, attestationEvidence); err != nil {
		t.Fatalf("insert attestation evidence: %v", err)
	}
	if err := repositories.Builds.InsertBuildAttestation(ctx, domain.BuildAttestation{ID: "att_repository", TenantID: tenant.ID, BuildID: "build_repository", EvidenceID: attestationEvidence.ID, PayloadHash: attestationEvidence.PayloadHash, PayloadSize: 42, PayloadType: "application/vnd.in-toto+json", PredicateType: "https://slsa.dev/provenance/v1", SubjectDigests: []string{artifact.Digest}, VerificationStatus: "structurally_valid", SchemaVersion: domain.BuildAttestationSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert build attestation: %v", err)
	}
	if err := repositories.Controls.InsertControlEvidence(ctx, domain.ControlEvidence{ID: "ce_repository", TenantID: tenant.ID, ControlID: control.ID, EvidenceType: "sbom", SubjectType: "evidence", SubjectID: evidence.ID, ProductID: product.ID, ReleaseID: release.ID, Confidence: "high", SchemaVersion: domain.ControlEvidenceSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert control evidence: %v", err)
	}
	waiver := domain.Waiver{ID: "wv_repository", TenantID: tenant.ID, ScopeType: "release", ScopeID: release.ID, ControlID: control.ID, Owner: "security", Risk: "accepted temporarily", Reason: "repository test", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.WaiverSchemaVersion, CreatedAt: now}
	if err := repositories.Governance.InsertWaiver(ctx, waiver); err != nil {
		t.Fatalf("insert waiver: %v", err)
	}
	waiver.Approved = true
	waiver.ApprovedBy = apiKey.ID
	waiver.ApprovedAt = &now
	if err := repositories.Governance.ApproveWaiver(ctx, waiver); err != nil {
		t.Fatalf("approve waiver: %v", err)
	}
	replacementWaiver := domain.Waiver{ID: "wv_repository_replacement", TenantID: tenant.ID, ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "accepted temporarily", Reason: "replacement", ExpiresAt: now.Add(2 * time.Hour), Supersedes: waiver.ID, SchemaVersion: domain.WaiverSchemaVersion, CreatedAt: now}
	if err := repositories.Governance.InsertWaiver(ctx, replacementWaiver); err != nil {
		t.Fatalf("supersede waiver: %v", err)
	}
	approval := domain.ApprovalRecord{ID: "apr_repository", TenantID: tenant.ID, SubjectType: "release", SubjectID: release.ID, Decision: "approved", Reason: "repository test", ApproverID: apiKey.ID, EvidenceID: evidence.ID, SchemaVersion: domain.ApprovalRecordSchemaVersion, CreatedAt: now}
	if err := repositories.Governance.InsertApprovalRecord(ctx, approval); err != nil {
		t.Fatalf("insert approval record: %v", err)
	}
	profile := domain.RedactionProfile{ID: "rp_repository", TenantID: tenant.ID, Name: "Repository", AllowedTypes: []string{"sbom"}, ExcludedFields: []string{"payload"}, SchemaVersion: domain.RedactionProfileSchemaVersion, CreatedAt: now}
	if err := repositories.Governance.InsertRedactionProfile(ctx, profile); err != nil {
		t.Fatalf("insert redaction profile: %v", err)
	}
	customerPackage := domain.CustomerSecurityPackage{ID: "customer_package_repository_port", TenantID: tenant.ID, ProductID: product.ID, ReleaseID: release.ID, RedactionProfileID: profile.ID, Title: "Repository customer package", State: "generated", Manifest: map[string]any{"release_id": release.ID}, ManifestHash: "sha256:" + strings.Repeat("4", 64), ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.CustomerPackageSchemaVersion, CreatedAt: now}
	if err := repositories.Packages.InsertCustomerSecurityPackage(ctx, customerPackage); err != nil {
		t.Fatalf("insert customer security package: %v", err)
	}
	accessedCustomerPackage := customerPackage
	accessedCustomerPackage.AccessCount++
	if err := repositories.Packages.UpdateCustomerSecurityPackageAccess(ctx, customerPackage, accessedCustomerPackage); err != nil {
		t.Fatalf("record customer security package access: %v", err)
	}
	if err := repositories.Packages.UpdateCustomerSecurityPackageAccess(ctx, customerPackage, accessedCustomerPackage); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale customer security package access err=%v, want conflict", err)
	}
	if err := repositories.Packages.InsertEvidenceBundleImport(ctx, domain.EvidenceBundleImport{ID: "bundle_import_repository", TenantID: tenant.ID, BundleHash: "sha256:" + strings.Repeat("5", 64), Result: "accepted", ImportedCount: 1, SchemaVersion: domain.EvidenceBundleImportVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert evidence bundle import: %v", err)
	}
	if err := repositories.Governance.InsertDSSETrustRoot(ctx, domain.DSSETrustRoot{ID: "dtr_repository", TenantID: tenant.ID, Name: "Repository root", KeyID: "repository-root", Algorithm: "Ed25519", PublicKey: strings.Repeat("A", 43) + "=", Status: "active", SchemaVersion: domain.DSSETrustRootSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert DSSE trust root: %v", err)
	}
	exception := domain.Exception{ID: "ex_repository", TenantID: tenant.ID, ReleaseID: release.ID, ControlID: control.ID, Reason: "repository test", Owner: "security", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := repositories.Decisions.InsertException(ctx, exception); err != nil {
		t.Fatalf("insert exception: %v", err)
	}
	exception.Approved = true
	exception.ApprovedBy = apiKey.ID
	exception.ApprovedAt = &now
	if err := repositories.Decisions.ApproveException(ctx, exception); err != nil {
		t.Fatalf("approve exception: %v", err)
	}
	if err := repositories.Governance.InsertLegalHold(ctx, domain.LegalHold{ID: "lh_repository", TenantID: tenant.ID, ScopeType: "release", ScopeID: release.ID, Reason: "repository test", Owner: "legal", SchemaVersion: domain.LegalHoldSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert legal hold: %v", err)
	}
	if err := repositories.Governance.InsertRetentionOverride(ctx, domain.RetentionOverride{ID: "ro_repository", TenantID: tenant.ID, ScopeType: "evidence", ScopeID: evidence.ID, RetentionUntil: now.Add(time.Hour), Reason: "repository test", Owner: "security", SchemaVersion: domain.RetentionOverrideSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert retention override: %v", err)
	}
	replacementEvidence := evidence
	replacementEvidence.ID = "evi_repository_replacement"
	replacementEvidence.Title = "Repository replacement SBOM"
	replacementEvidence.CanonicalHash = "sha256:replacement"
	if err := repositories.Evidence.InsertEvidence(ctx, replacementEvidence); err != nil {
		t.Fatalf("insert replacement evidence: %v", err)
	}
	linkedEvidence := evidence
	linkedEvidence.RelatedEvidenceRefs = []domain.EvidenceRef{{Type: "product", ID: product.ID, Relationship: "linked_to"}}
	if err := repositories.Evidence.UpdateEvidenceLinks(ctx, linkedEvidence); err != nil {
		t.Fatalf("update evidence links: %v", err)
	}
	supersededEvidence := linkedEvidence
	supersededEvidence.SupersededBy = replacementEvidence.ID
	replacementEvidence.Supersedes = supersededEvidence.ID
	if err := repositories.Evidence.RecordSupersession(ctx, supersededEvidence, replacementEvidence); err != nil {
		t.Fatalf("record evidence supersession: %v", err)
	}
	if err := repositories.Evidence.AppendLifecycle(ctx, domain.EvidenceLifecycleEvent{ID: "elc_repository", TenantID: tenant.ID, EvidenceID: evidence.ID, Action: "accepted", Reason: "test", ActorID: "key_repository", SchemaVersion: domain.EvidenceLifecycleSchemaVersion, CreatedAt: now, Details: map[string]any{"source": "test"}}); err != nil {
		t.Fatalf("append lifecycle: %v", err)
	}
	if err := repositories.Evidence.InsertSBOM(ctx, domain.SBOM{ID: "sbom_repository", TenantID: tenant.ID, EvidenceID: evidence.ID, ReleaseID: release.ID, ArtifactID: artifact.ID, Format: "cyclonedx", SpecVersion: "1.6", ComponentCount: 1, Components: []domain.SBOMComponent{{Name: "repository"}}, CreatedAt: now}); err != nil {
		t.Fatalf("insert SBOM: %v", err)
	}
	scan := domain.VulnerabilityScan{ID: "scan_repository", TenantID: tenant.ID, EvidenceID: evidence.ID, ReleaseID: release.ID, Scanner: "test", TargetRef: "pkg:oci/repository", Summary: map[string]int{}, Findings: []domain.VulnerabilityFinding{}, CreatedAt: now}
	if err := repositories.Evidence.InsertVulnerabilityScan(ctx, scan); err != nil {
		t.Fatalf("insert vulnerability scan: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO artifact_signatures (
			id, tenant_id, artifact_id, subject_digest, algorithm, signature,
			verification_status, schema_version, created_at
		)
		VALUES ('artsig_repository', $1, $2, $3, 'Ed25519', 'signature', 'recorded', 'artifact-signature.v1.0.0', $4)
	`, tenant.ID, artifact.ID, artifact.Digest, now); err != nil {
		t.Fatalf("seed artifact signature: %v", err)
	}
	if err := repositories.Builds.InsertCollectorRelease(ctx, domain.CollectorRelease{ID: "colrel_repository_complete", TenantID: tenant.ID, CollectorID: collector.ID, Version: "1.1.0", ArtifactDigest: artifact.Digest, SignatureID: "artsig_repository", SBOMID: "sbom_repository", ScanID: scan.ID, Pinned: true, VerificationStatus: "evidence_complete", HealthStatus: "healthy", Limitations: []string{"test"}, SchemaVersion: domain.CollectorReleaseSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert complete collector release: %v", err)
	}
	if err := repositories.Evidence.InsertOpenAPIContract(ctx, domain.OpenAPIContract{ID: "oas_repository", TenantID: tenant.ID, ProductID: product.ID, ReleaseID: release.ID, Version: "v1", Hash: "sha256:openapi", PathCount: 1, Operations: []domain.OpenAPIOperation{}, EvidenceID: evidence.ID, CreatedAt: now}); err != nil {
		t.Fatalf("insert OpenAPI contract: %v", err)
	}
	candidate := domain.ReleaseCandidate{ID: "rc_repository", TenantID: tenant.ID, ReleaseID: release.ID, Name: "Repository candidate", State: "open", SnapshotHash: "sha256:candidate", SchemaVersion: domain.ReleaseCandidateSchemaVersion, CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertReleaseCandidate(ctx, candidate); err != nil {
		t.Fatalf("insert release candidate: %v", err)
	}
	candidate.State = "promoted"
	candidate.PromotedAt = &now
	if err := repositories.ReleaseCatalog.UpdateReleaseCandidateState(ctx, candidate, "open"); err != nil {
		t.Fatalf("update release candidate state: %v", err)
	}
	vex := domain.VEXDocument{ID: "vex_repository", TenantID: tenant.ID, EvidenceID: evidence.ID, ReleaseID: release.ID, ArtifactID: artifact.ID, Format: "openvex", Author: "repository test", StatementCount: 1, StatusSummary: map[string]int{"not_affected": 1}, SchemaVersion: domain.VEXDocumentSchemaVersion, CreatedAt: now}
	if err := repositories.Evidence.InsertVEXDocument(ctx, vex); err != nil {
		t.Fatalf("insert VEX document: %v", err)
	}
	if err := repositories.Evidence.InsertVEXImportReport(ctx, domain.VEXImportReport{ID: "vexrep_repository", TenantID: tenant.ID, VEXDocumentID: vex.ID, EvidenceID: evidence.ID, ReleaseID: release.ID, ArtifactID: artifact.ID, ParserVersion: app.ParserVersionOpenVEXJSON, Status: "parsed", StatementCount: 1, UnsupportedFields: []string{}, Warnings: []string{}, InvalidStatements: []domain.VEXImportIssue{}, MappingFailures: []domain.VEXImportIssue{}, SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("insert VEX import report: %v", err)
	}
	decision := domain.VulnerabilityDecision{ID: "dec_repository", TenantID: tenant.ID, FindingID: "finding_repository", ScanID: "scan_repository", ReleaseID: release.ID, Vulnerability: "CVE-2026-0001", Status: "not_affected", Justification: "test decision", Source: "test", EvidenceID: evidence.ID, SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: now, SupportingRefs: []domain.SubjectRef{}}
	if err := repositories.Decisions.InsertVulnerabilityDecision(ctx, decision); err != nil {
		t.Fatalf("insert decision: %v", err)
	}
	replacementDecision := decision
	replacementDecision.ID = "dec_repository_replacement"
	replacementDecision.Status = "fixed"
	replacementDecision.Supersedes = decision.ID
	decision.SupersededBy = replacementDecision.ID
	if err := repositories.Decisions.SupersedeAndInsert(ctx, replacementDecision, []domain.VulnerabilityDecision{decision}); err != nil {
		t.Fatalf("supersede and insert decision: %v", err)
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
	signingKey.Status = "retiring"
	if err := repositories.Signatures.UpdateSigningKey(ctx, signingKey, "active"); err != nil {
		t.Fatalf("update signing key: %v", err)
	}
	if err := repositories.Signatures.UpdateSigningKey(ctx, signingKey, "active"); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale signing key update err=%v, want conflict", err)
	}
	if err := repositories.Signatures.InsertSignature(ctx, domain.Signature{ID: "sig_repository", TenantID: tenant.ID, SubjectType: "evidence_item", SubjectID: evidence.ID, KeyID: signingKey.ID, Algorithm: "Ed25519", Value: "signature", CreatedAt: now}); err != nil {
		t.Fatalf("insert signature: %v", err)
	}
	if err := repositories.Integrity.InsertSigningProvider(ctx, domain.SigningProvider{ID: "provider_repository", TenantID: tenant.ID, Name: "Repository KMS", Type: "aws_kms", Status: "active", KeyRef: "arn:aws:kms:example", Encrypted: true, SchemaVersion: domain.SigningProviderSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert signing provider: %v", err)
	}
	if err := repositories.Future.InsertSigningOperation(ctx, domain.Signature{ID: "provider_signature_repository", TenantID: tenant.ID, SubjectType: "release", SubjectID: release.ID, KeyID: "provider_repository", Algorithm: "external-aws_kms", Value: "provider-receipt", CreatedAt: now}, domain.SigningOperation{ID: "signing_operation_repository", TenantID: tenant.ID, ProviderID: "provider_repository", SubjectType: "release", SubjectID: release.ID, PayloadHash: "sha256:" + strings.Repeat("A", 64), SignatureRef: "provider_signature_repository", Result: "passed", Checks: []domain.VerifyCheck{{Name: "provider_active", Result: "passed"}}, SchemaVersion: domain.SigningOperationVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert signing operation: %v", err)
	}
	if err := repositories.Future.InsertAnomalyReport(ctx, domain.AnomalyReport{ID: "anomaly_repository", TenantID: tenant.ID, SubjectType: "release", SubjectID: release.ID, Result: "attention_required", Signals: []domain.AnomalySignal{{Name: "missing_passed_build", Severity: "medium", Detail: "No passed build run is linked to this release."}}, Assumptions: []string{"stored evidence"}, Limitations: []string{"evidence anomalies only"}, SchemaVersion: domain.AnomalyReportVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert anomaly report: %v", err)
	}
	for _, subject := range []struct {
		typeName string
		id       string
	}{
		{typeName: "tenant", id: tenant.ID},
		{typeName: "product", id: product.ID},
		{typeName: "evidence", id: evidence.ID},
		{typeName: "build", id: "build_repository"},
		{typeName: "customer_package", id: "pkg_repository"},
	} {
		signatureID := "provider_signature_" + subject.typeName
		operationID := "signing_operation_" + subject.typeName
		if err := repositories.Future.InsertSigningOperation(ctx, domain.Signature{ID: signatureID, TenantID: tenant.ID, SubjectType: subject.typeName, SubjectID: subject.id, KeyID: "provider_repository", Algorithm: "external-aws_kms", Value: "provider-receipt", CreatedAt: now}, domain.SigningOperation{ID: operationID, TenantID: tenant.ID, ProviderID: "provider_repository", SubjectType: subject.typeName, SubjectID: subject.id, PayloadHash: "sha256:" + strings.Repeat("d", 64), SignatureRef: signatureID, Result: "passed", Checks: []domain.VerifyCheck{{Name: "provider_active", Result: "passed"}}, SchemaVersion: domain.SigningOperationVersion, CreatedAt: now}); err != nil {
			t.Fatalf("insert %s signing operation: %v", subject.typeName, err)
		}
	}
	if err := repositories.Integrity.InsertSigningProvider(ctx, domain.SigningProvider{ID: "provider_repository_inactive", TenantID: tenant.ID, Name: "Repository inactive KMS", Type: "aws_kms", Status: "inactive", KeyRef: "arn:aws:kms:inactive", Encrypted: true, SchemaVersion: domain.SigningProviderSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert inactive signing provider: %v", err)
	}
	if err := repositories.Future.InsertSigningOperation(ctx, domain.Signature{ID: "provider_signature_inactive", TenantID: tenant.ID, SubjectType: "release", SubjectID: release.ID, KeyID: "provider_repository_inactive", Algorithm: "external-aws_kms", Value: "provider-receipt", CreatedAt: now}, domain.SigningOperation{ID: "signing_operation_inactive", TenantID: tenant.ID, ProviderID: "provider_repository_inactive", SubjectType: "release", SubjectID: release.ID, PayloadHash: "sha256:" + strings.Repeat("b", 64), SignatureRef: "provider_signature_inactive", Result: "passed", Checks: []domain.VerifyCheck{{Name: "provider_active", Result: "passed"}}, SchemaVersion: domain.SigningOperationVersion, CreatedAt: now}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("inactive signing operation err=%v, want validation", err)
	}
	if err := repositories.Future.InsertSigningOperation(ctx, domain.Signature{ID: "provider_signature_bad_digest", TenantID: tenant.ID, SubjectType: "release", SubjectID: release.ID, KeyID: "provider_repository", Algorithm: "external-aws_kms", Value: "provider-receipt", CreatedAt: now}, domain.SigningOperation{ID: "signing_operation_bad_digest", TenantID: tenant.ID, ProviderID: "provider_repository", SubjectType: "release", SubjectID: release.ID, PayloadHash: "sha256:not-a-digest", SignatureRef: "provider_signature_bad_digest", Result: "passed", Checks: []domain.VerifyCheck{{Name: "provider_active", Result: "passed"}}, SchemaVersion: domain.SigningOperationVersion, CreatedAt: now}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("malformed signing operation digest err=%v, want validation", err)
	}
	if err := repositories.Future.InsertSigningOperation(ctx, domain.Signature{ID: "provider_signature_missing_subject", TenantID: tenant.ID, SubjectType: "release", SubjectID: "missing-release", KeyID: "provider_repository", Algorithm: "external-aws_kms", Value: "provider-receipt", CreatedAt: now}, domain.SigningOperation{ID: "signing_operation_missing_subject", TenantID: tenant.ID, ProviderID: "provider_repository", SubjectType: "release", SubjectID: "missing-release", PayloadHash: "sha256:" + strings.Repeat("c", 64), SignatureRef: "provider_signature_missing_subject", Result: "passed", Checks: []domain.VerifyCheck{{Name: "provider_active", Result: "passed"}}, SchemaVersion: domain.SigningOperationVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing signing operation subject err=%v, want not found", err)
	}
	if err := repositories.Future.InsertPublicTransparencyLog(ctx, domain.PublicTransparencyLog{ID: "public_log_repository", TenantID: tenant.ID, Name: "Repository log", Endpoint: "https://transparency.example.test", PublicKey: "public-key", State: "configured", SchemaVersion: domain.PublicTransparencyLogVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert public transparency log: %v", err)
	}
	if err := repositories.Future.InsertEvidenceSummary(ctx, domain.EvidenceSummary{ID: "summary_repository", TenantID: tenant.ID, SubjectType: "release", SubjectID: release.ID, EvidenceIDs: []string{evidence.ID}, Summary: "Repository evidence", Citations: []domain.EvidenceCitation{{EvidenceID: evidence.ID, Type: evidence.Type, Title: evidence.Title, CanonicalHash: evidence.CanonicalHash}}, SchemaVersion: domain.EvidenceSummaryVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert evidence summary: %v", err)
	}
	if err := repositories.Future.InsertEvidenceGraphSnapshot(ctx, domain.EvidenceGraphSnapshot{ID: "graph_repository", TenantID: tenant.ID, ProductID: product.ID, ReleaseID: release.ID, Nodes: []domain.GraphNode{}, Edges: []domain.GraphEdge{}, GraphHash: "sha256:graph", SchemaVersion: domain.EvidenceGraphSnapshotVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert evidence graph snapshot: %v", err)
	}
	if err := repositories.Future.InsertSaaSEditionProfile(ctx, domain.SaaSEditionProfile{ID: "saas_repository", TenantID: tenant.ID, Name: "Repository", Region: "eu", AdminTenantID: tenant.ID, IsolationModel: "shared-control-plane", Status: "proposed", ConfigHash: "sha256:config", SchemaVersion: domain.SaaSEditionProfileVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert SaaS edition profile: %v", err)
	}
	if err := repositories.Future.InsertMarketplaceCollector(ctx, domain.MarketplaceCollector{ID: "marketplace_repository", TenantID: tenant.ID, Name: "Repository", Provider: "scanner", Version: "1.0.0", Publisher: "vendor", ManifestHash: "sha256:manifest", State: "registered", SchemaVersion: domain.MarketplaceCollectorVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert marketplace collector: %v", err)
	}
	if err := repositories.Enterprise.InsertQuestionnaireTemplate(ctx, domain.QuestionnaireTemplate{ID: "template_repository", TenantID: tenant.ID, Name: "Repository", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q1", Prompt: "Is evidence available?"}}, SchemaVersion: domain.QuestionnaireTemplateVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert questionnaire template: %v", err)
	}
	if err := repositories.Enterprise.InsertQuestionnaireAnswerLibraryEntry(ctx, domain.QuestionnaireAnswerLibraryEntry{ID: "answer_repository", TenantID: tenant.ID, QuestionID: "q1", EvidenceType: evidence.Type, ControlID: control.ID, ProductID: product.ID, ReleaseID: release.ID, Answer: "Evidence is available.", EvidenceIDs: []string{evidence.ID}, Limitations: []string{"human review required"}, SchemaVersion: domain.QuestionnaireAnswerLibraryVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert questionnaire answer library entry: %v", err)
	}
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, domain.QuestionnairePackage{ID: "questionnaire_package_repository", TenantID: tenant.ID, TemplateID: "template_repository", PackageID: "pkg_repository", ProductID: product.ID, ReleaseID: release.ID, Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Evidence is available.", EvidenceIDs: []string{evidence.ID}}}, ManifestHash: "sha256:" + strings.Repeat("a", 64), SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert questionnaire package: %v", err)
	}
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, domain.QuestionnairePackage{ID: "questionnaire_package_repository_unscoped", TenantID: tenant.ID, TemplateID: "template_repository", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Evidence has not been scoped."}}, ManifestHash: "sha256:" + strings.Repeat("b", 64), SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert unscoped questionnaire package: %v", err)
	}
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, domain.QuestionnairePackage{ID: "questionnaire_package_repository_missing_package", TenantID: tenant.ID, TemplateID: "template_repository", PackageID: "missing-package", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Evidence has not been scoped."}}, ManifestHash: "sha256:" + strings.Repeat("c", 64), SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing questionnaire customer package err=%v, want not found", err)
	}
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, domain.QuestionnairePackage{ID: "questionnaire_package_repository_missing_template", TenantID: tenant.ID, TemplateID: "missing-template", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Evidence has not been scoped."}}, ManifestHash: "sha256:" + strings.Repeat("d", 64), SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing questionnaire template err=%v, want not found", err)
	}
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, domain.QuestionnairePackage{ID: "questionnaire_package_repository_missing_product", TenantID: tenant.ID, TemplateID: "template_repository", ProductID: "missing-product", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Evidence has not been scoped."}}, ManifestHash: "sha256:" + strings.Repeat("e", 64), SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing questionnaire product err=%v, want not found", err)
	}
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, domain.QuestionnairePackage{ID: "questionnaire_package_repository_missing_release", TenantID: tenant.ID, TemplateID: "template_repository", ProductID: product.ID, ReleaseID: "missing-release", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Evidence has not been scoped."}}, ManifestHash: "sha256:" + strings.Repeat("f", 64), SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing questionnaire release err=%v, want not found", err)
	}
	if err := repositories.Enterprise.InsertQuestionnairePackage(ctx, domain.QuestionnairePackage{ID: "questionnaire_package_repository_missing_evidence", TenantID: tenant.ID, TemplateID: "template_repository", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Evidence is unavailable.", EvidenceIDs: []string{"missing-evidence"}}}, ManifestHash: "sha256:" + strings.Repeat("0", 64), SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing questionnaire evidence err=%v, want not found", err)
	}
	if err := repositories.Enterprise.InsertQuestionnaireAnswerLibraryEntry(ctx, domain.QuestionnaireAnswerLibraryEntry{ID: "answer_repository_release_only", TenantID: tenant.ID, QuestionID: "q2", ReleaseID: release.ID, Answer: "Release-scoped evidence is available.", Limitations: []string{"human review required"}, SchemaVersion: domain.QuestionnaireAnswerLibraryVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert release-only questionnaire answer library entry: %v", err)
	}
	if err := repositories.Future.InsertPDFReportPackage(ctx, domain.PDFReportPackage{ID: "pdf_repository", TenantID: tenant.ID, ReportType: "release_readiness", ProductID: product.ID, ReleaseID: release.ID, Title: "Repository report", PayloadHash: "sha256:report", PayloadSize: 1, SchemaVersion: domain.PDFReportPackageVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert PDF report package: %v", err)
	}
	if err := repositories.Future.InsertQuestionnaireDraft(ctx, domain.QuestionnaireDraft{ID: "draft_repository", TenantID: tenant.ID, TemplateID: "template_repository", ProductID: product.ID, ReleaseID: release.ID, Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Evidence is available.", EvidenceIDs: []string{evidence.ID}}}, ManifestHash: "sha256:draft", SchemaVersion: domain.QuestionnaireDraftVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert questionnaire draft: %v", err)
	}
	if err := repositories.Future.InsertPublicTransparencyLog(ctx, domain.PublicTransparencyLog{ID: "public_log_repository_http", TenantID: tenant.ID, Name: "Repository insecure log", Endpoint: "http://transparency.example.test", PublicKey: "public-key", State: "configured", SchemaVersion: domain.PublicTransparencyLogVersion, CreatedAt: now}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("insecure public transparency log err=%v, want validation", err)
	}
	if err := repositories.Integrity.InsertCosignVerification(ctx, domain.CosignVerification{ID: "cosign_repository", TenantID: tenant.ID, ArtifactID: artifact.ID, ContainerImageID: "img_repository", ArtifactSignatureID: "artsig_repository_port", SubjectDigest: artifact.Digest, Result: "limited", Checks: []domain.VerifyCheck{{Name: "recorded", Result: "passed"}}, SchemaVersion: domain.CosignVerificationSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert Cosign verification: %v", err)
	}
	if err := repositories.Integrity.InsertSigningProvider(ctx, domain.SigningProvider{ID: "provider_repository_secret", TenantID: tenant.ID, Name: "Secret native provider", Type: "native_pkcs11_hsm", Status: "active", KeyRef: "pkcs11:token=release;object=key;pin-value=secret", Encrypted: true, SchemaVersion: domain.SigningProviderSchemaVersion, CreatedAt: now}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("secret-bearing signing provider err=%v, want validation", err)
	}
	retentionPolicy := domain.ObjectRetentionPolicy{ID: "retention_repository", TenantID: tenant.ID, Name: "Repository retention", ObjectPrefix: "tenants/" + tenant.ID + "/", ObjectKey: "tenants/" + tenant.ID + "/raw/evidence.json", Mode: "governance", RetentionDays: 30, MaxVerificationAgeHours: 24, Status: "configured", SchemaVersion: domain.ObjectRetentionPolicyVersion, CreatedAt: now}
	if err := repositories.Integrity.InsertObjectRetentionPolicy(ctx, retentionPolicy); err != nil {
		t.Fatalf("insert object retention policy: %v", err)
	}
	retentionPolicy.Status = "not_verified"
	retentionPolicy.VerifiedAt = &now
	retentionPolicy.VerificationHash = "sha256:retention"
	retentionPolicy.VerificationChecks = []domain.VerifyCheck{{Name: "recorded", Result: "passed"}}
	if err := repositories.Integrity.UpdateObjectRetentionPolicy(ctx, retentionPolicy, "configured"); err != nil {
		t.Fatalf("update object retention policy: %v", err)
	}
	if err := repositories.Integrity.UpdateObjectRetentionPolicy(ctx, retentionPolicy, "configured"); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale object retention policy update err=%v, want conflict", err)
	}
	if err := repositories.Integrity.InsertBackupManifest(ctx, domain.BackupManifest{ID: "backup_repository", TenantID: tenant.ID, StateHash: "sha256:backup", ResourceCounts: map[string]int{"evidence": 1}, ConsistencyChecks: []domain.VerifyCheck{{Name: "chain", Result: "passed"}}, SchemaVersion: domain.BackupManifestSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert backup manifest: %v", err)
	}
	merkleBatch := domain.MerkleBatch{ID: "merkle_repository", TenantID: tenant.ID, FromSequence: 1, ToSequence: 1, EntryCount: 1, LeafHashes: []string{"sha256:leaf"}, RootHash: "sha256:root", SchemaVersion: domain.MerkleBatchSchemaVersion, CreatedAt: now}
	if err := repositories.Integrity.InsertMerkleBatch(ctx, merkleBatch); err != nil {
		t.Fatalf("insert Merkle batch: %v", err)
	}
	if err := repositories.Integrity.InsertTransparencyCheckpoint(ctx, domain.TransparencyCheckpoint{ID: "checkpoint_repository", TenantID: tenant.ID, BatchID: merkleBatch.ID, Provider: "rfc3161", ExternalID: "checkpoint", TimestampHash: "sha256:checkpoint", State: "recorded", SchemaVersion: domain.TransparencyCheckpointVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert transparency checkpoint: %v", err)
	}
	if err := repositories.Future.InsertPublicTransparencyLogEntry(ctx, domain.PublicTransparencyLogEntry{ID: "public_entry_repository", TenantID: tenant.ID, LogID: "public_log_repository", CheckpointID: "checkpoint_repository", MerkleBatchID: merkleBatch.ID, ExternalID: "entry", EntryHash: "sha256:entry", State: "published", SchemaVersion: domain.PublicTransparencyEntryVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert public transparency entry: %v", err)
	}
	verifiedAt := now
	verifiedPublicEntry := domain.PublicTransparencyLogEntry{ID: "public_entry_repository", TenantID: tenant.ID, LogID: "public_log_repository", CheckpointID: "checkpoint_repository", MerkleBatchID: merkleBatch.ID, ExternalID: "entry", EntryHash: "sha256:entry", State: "inclusion_verified", InclusionRootHash: "sha256:root", InclusionProofHash: "sha256:proof", InclusionVerifiedAt: &verifiedAt, VerificationChecks: []domain.VerifyCheck{{Name: "proof", Result: "passed"}}, SchemaVersion: domain.PublicTransparencyEntryVersion, CreatedAt: now}
	if err := repositories.Future.UpdatePublicTransparencyLogEntry(ctx, verifiedPublicEntry, "published"); err != nil {
		t.Fatalf("update public transparency entry: %v", err)
	}
	if err := repositories.Future.UpdatePublicTransparencyLogEntry(ctx, verifiedPublicEntry, "published"); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale public transparency entry update err=%v, want conflict", err)
	}
	if err := repositories.Packages.InsertReleaseBundle(ctx, domain.ReleaseBundle{ID: "bundle_repository", TenantID: tenant.ID, ReleaseID: release.ID, State: "generated", Manifest: map[string]any{"release_id": release.ID}, ManifestHash: "sha256:manifest", SignatureRefs: []string{"sig_repository"}, CreatedAt: now}); err != nil {
		t.Fatalf("insert release bundle: %v", err)
	}
	if err := repositories.Packages.InsertHTMLReportPackage(ctx, domain.HTMLReportPackage{ID: "html_repository", TenantID: tenant.ID, ReportType: "cra_readiness", ProductID: product.ID, ReleaseID: release.ID, HTML: "<html></html>", Hash: "sha256:" + strings.Repeat("1", 64), SchemaVersion: "html-report-package.v1.0.0", CreatedAt: now}); err != nil {
		t.Fatalf("insert HTML report package: %v", err)
	}
	template := domain.CustomReportTemplate{ID: "report_template_repository", TenantID: tenant.ID, Name: "Repository", Version: "1", ReportType: "evidence", AllowedFields: []string{"subject_id"}, Template: "json", SchemaVersion: domain.ReportTemplateSchemaVersion, CreatedAt: now}
	if err := repositories.Packages.InsertCustomReportTemplate(ctx, template); err != nil {
		t.Fatalf("insert custom report template: %v", err)
	}
	if err := repositories.Packages.InsertRenderedCustomReport(ctx, domain.RenderedCustomReport{ID: "rendered_report_repository", TenantID: tenant.ID, TemplateID: template.ID, SubjectType: "release", SubjectID: release.ID, Output: map[string]any{"subject_id": release.ID}, Hash: "sha256:" + strings.Repeat("2", 64), SchemaVersion: "rendered-report.v1.0.0", CreatedAt: now}); err != nil {
		t.Fatalf("insert rendered custom report: %v", err)
	}
	if err := repositories.Packages.InsertRenderedCustomReport(ctx, domain.RenderedCustomReport{ID: "rendered_report_repository_missing_template", TenantID: tenant.ID, TemplateID: "missing-template", SubjectType: "release", SubjectID: release.ID, Output: map[string]any{}, Hash: "sha256:" + strings.Repeat("3", 64), SchemaVersion: "rendered-report.v1.0.0", CreatedAt: now}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing custom report template err=%v, want not found", err)
	}
	verification := domain.VerificationResult{ID: "verify_repository", TenantID: tenant.ID, SubjectType: "evidence_item", SubjectID: evidence.ID, Result: "limited", Checks: []domain.VerifyCheck{{Name: "recorded", Result: "passed"}}, Profile: domain.VerificationProfile{ID: "repository-verification-profile", Version: domain.VerificationProfileSchemaVersion, RequiredChecks: []string{"recorded"}, Limitations: []string{"repository test"}}, Limitations: []string{"repository test"}, SchemaVersion: domain.VerificationResultSchemaVersion, VerifiedAt: now}
	if err := repositories.Verification.InsertVerificationResult(ctx, verification); err != nil {
		t.Fatalf("insert verification result: %v", err)
	}
	var verificationProfileID string
	if err := tx.QueryRow(ctx, `SELECT assurance_profile ->> 'id' FROM verification_results WHERE id = $1 AND tenant_id = $2`, verification.ID, tenant.ID).Scan(&verificationProfileID); err != nil {
		t.Fatalf("read verification assurance profile: %v", err)
	}
	if verificationProfileID != verification.Profile.ID {
		t.Fatalf("verification assurance profile id = %q, want %q", verificationProfileID, verification.Profile.ID)
	}
	if err := repositories.Verification.InsertPolicyEvaluation(ctx, domain.PolicyEvaluation{ID: "policy_repository", TenantID: tenant.ID, ReleaseID: release.ID, Result: "passed", PolicySet: domain.PolicySetVersion, Checks: []domain.PolicyCheck{{Name: "recorded", Result: "passed", Severity: "low", Explanation: "test"}}, CreatedAt: now}); err != nil {
		t.Fatalf("insert policy evaluation: %v", err)
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
		{"api key usage", repositories.Identity.UpdateAPIKeyLastUsed(ctx, domain.APIKey{})},
		{"collector usage", repositories.Identity.UpdateCollectorLastSeen(ctx, domain.Collector{})},
		{"organization", repositories.Identity.InsertOrganization(ctx, domain.Organization{})},
		{"human user", repositories.Identity.InsertHumanUser(ctx, domain.HumanUser{})},
		{"human user deactivation", repositories.Identity.DeactivateHumanUser(ctx, domain.HumanUser{})},
		{"role binding", repositories.Identity.InsertRoleBinding(ctx, domain.RoleBinding{})},
		{"SSO provider", repositories.Identity.InsertSSOProvider(ctx, domain.SSOProvider{})},
		{"SSO trust material", repositories.Identity.UpdateSSOProviderTrustMaterial(ctx, domain.SSOProvider{})},
		{"identity link", repositories.Identity.InsertUserIdentityLink(ctx, domain.UserIdentityLink{})},
		{"provider verification", repositories.Identity.InsertProviderVerification(ctx, domain.ProviderVerification{})},
		{"SSO session", repositories.Identity.InsertSSOSession(ctx, domain.SSOSession{})},
		{"SSO session validation", repositories.Identity.ValidateActiveSSOSession(ctx, domain.SSOSession{}, time.Time{})},
		{"SSO session revocation", repositories.Identity.RevokeSSOSession(ctx, domain.SSOSession{})},
		{"customer portal access", repositories.Identity.InsertCustomerPortalAccess(ctx, domain.CustomerPortalAccess{})},
		{"customer portal access update", repositories.Identity.UpdateCustomerPortalAccess(ctx, domain.CustomerPortalAccess{}, domain.CustomerPortalAccess{})},
		{"control framework", repositories.Controls.InsertControlFramework(ctx, domain.ControlFramework{})},
		{"security control", repositories.Controls.InsertSecurityControl(ctx, domain.SecurityControl{})},
		{"control evidence", repositories.Controls.InsertControlEvidence(ctx, domain.ControlEvidence{})},
		{"waiver", repositories.Governance.InsertWaiver(ctx, domain.Waiver{})},
		{"waiver approval", repositories.Governance.ApproveWaiver(ctx, domain.Waiver{})},
		{"approval record", repositories.Governance.InsertApprovalRecord(ctx, domain.ApprovalRecord{})},
		{"redaction profile", repositories.Governance.InsertRedactionProfile(ctx, domain.RedactionProfile{})},
		{"DSSE trust root", repositories.Governance.InsertDSSETrustRoot(ctx, domain.DSSETrustRoot{})},
		{"exception", repositories.Decisions.InsertException(ctx, domain.Exception{})},
		{"exception approval", repositories.Decisions.ApproveException(ctx, domain.Exception{})},
		{"legal hold", repositories.Governance.InsertLegalHold(ctx, domain.LegalHold{})},
		{"retention override", repositories.Governance.InsertRetentionOverride(ctx, domain.RetentionOverride{})},
		{"collector", repositories.Builds.InsertCollector(ctx, domain.Collector{})},
		{"collector release", repositories.Builds.InsertCollectorRelease(ctx, domain.CollectorRelease{})},
		{"build run", repositories.Builds.InsertBuildRun(ctx, domain.BuildRun{})},
		{"build attestation", repositories.Builds.InsertBuildAttestation(ctx, domain.BuildAttestation{})},
		{"container image", repositories.SupplyChain.InsertContainerImage(ctx, domain.ContainerImage{})},
		{"artifact signature", repositories.SupplyChain.InsertArtifactSignature(ctx, domain.ArtifactSignature{})},
		{"source repository", repositories.Source.InsertSourceRepository(ctx, domain.SourceRepository{})},
		{"source commit", repositories.Source.InsertSourceCommit(ctx, domain.SourceCommit{})},
		{"source branch", repositories.Source.InsertSourceBranch(ctx, domain.SourceBranch{})},
		{"source branch update", repositories.Source.UpdateSourceBranch(ctx, domain.SourceBranch{})},
		{"pull request", repositories.Source.InsertPullRequest(ctx, domain.PullRequest{})},
		{"product", repositories.ReleaseCatalog.InsertProduct(ctx, domain.Product{})},
		{"project", repositories.ReleaseCatalog.InsertProject(ctx, domain.Project{})},
		{"release", repositories.ReleaseCatalog.InsertRelease(ctx, domain.Release{})},
		{"release state", repositories.ReleaseCatalog.UpdateReleaseState(ctx, domain.Release{}, "")},
		{"artifact", repositories.ReleaseCatalog.InsertArtifact(ctx, domain.Artifact{})},
		{"release candidate", repositories.ReleaseCatalog.InsertReleaseCandidate(ctx, domain.ReleaseCandidate{})},
		{"release candidate state", repositories.ReleaseCatalog.UpdateReleaseCandidateState(ctx, domain.ReleaseCandidate{}, "")},
		{"evidence", repositories.Evidence.InsertEvidence(ctx, domain.EvidenceItem{})},
		{"evidence links", repositories.Evidence.UpdateEvidenceLinks(ctx, domain.EvidenceItem{})},
		{"evidence supersession", repositories.Evidence.RecordSupersession(ctx, domain.EvidenceItem{}, domain.EvidenceItem{})},
		{"lifecycle", repositories.Evidence.AppendLifecycle(ctx, domain.EvidenceLifecycleEvent{})},
		{"SBOM", repositories.Evidence.InsertSBOM(ctx, domain.SBOM{})},
		{"vulnerability scan", repositories.Evidence.InsertVulnerabilityScan(ctx, domain.VulnerabilityScan{})},
		{"OpenAPI contract", repositories.Evidence.InsertOpenAPIContract(ctx, domain.OpenAPIContract{})},
		{"VEX document", repositories.Evidence.InsertVEXDocument(ctx, domain.VEXDocument{})},
		{"VEX import report", repositories.Evidence.InsertVEXImportReport(ctx, domain.VEXImportReport{})},
		{"decision", repositories.Decisions.InsertVulnerabilityDecision(ctx, domain.VulnerabilityDecision{})},
		{"superseding decision", repositories.Decisions.SupersedeAndInsert(ctx, domain.VulnerabilityDecision{}, nil)},
		{"idempotency", repositories.Idempotency.Insert(ctx, app.IdempotencyRecordKey{}, app.IdempotencyRecord{})},
		{"outbox", repositories.Outbox.Enqueue(ctx, app.OutboxJob{})},
		{"package", repositories.Packages.InsertReleaseBundle(ctx, domain.ReleaseBundle{})},
		{"customer security package", repositories.Packages.InsertCustomerSecurityPackage(ctx, domain.CustomerSecurityPackage{})},
		{"customer security package access", repositories.Packages.UpdateCustomerSecurityPackageAccess(ctx, domain.CustomerSecurityPackage{}, domain.CustomerSecurityPackage{})},
		{"evidence bundle import", repositories.Packages.InsertEvidenceBundleImport(ctx, domain.EvidenceBundleImport{})},
		{"HTML report package", repositories.Packages.InsertHTMLReportPackage(ctx, domain.HTMLReportPackage{})},
		{"custom report template", repositories.Packages.InsertCustomReportTemplate(ctx, domain.CustomReportTemplate{})},
		{"rendered custom report", repositories.Packages.InsertRenderedCustomReport(ctx, domain.RenderedCustomReport{})},
		{"signing key", repositories.Signatures.InsertSigningKey(ctx, domain.SigningKey{})},
		{"signing key update", repositories.Signatures.UpdateSigningKey(ctx, domain.SigningKey{}, "")},
		{"signature", repositories.Signatures.InsertSignature(ctx, domain.Signature{})},
		{"signing provider", repositories.Integrity.InsertSigningProvider(ctx, domain.SigningProvider{})},
		{"Cosign verification", repositories.Integrity.InsertCosignVerification(ctx, domain.CosignVerification{})},
		{"object retention policy", repositories.Integrity.InsertObjectRetentionPolicy(ctx, domain.ObjectRetentionPolicy{})},
		{"object retention policy update", repositories.Integrity.UpdateObjectRetentionPolicy(ctx, domain.ObjectRetentionPolicy{}, "")},
		{"backup manifest", repositories.Integrity.InsertBackupManifest(ctx, domain.BackupManifest{})},
		{"Merkle batch", repositories.Integrity.InsertMerkleBatch(ctx, domain.MerkleBatch{})},
		{"transparency checkpoint", repositories.Integrity.InsertTransparencyCheckpoint(ctx, domain.TransparencyCheckpoint{})},
		{"public transparency log", repositories.Future.InsertPublicTransparencyLog(ctx, domain.PublicTransparencyLog{})},
		{"public transparency entry", repositories.Future.InsertPublicTransparencyLogEntry(ctx, domain.PublicTransparencyLogEntry{})},
		{"public transparency entry update", repositories.Future.UpdatePublicTransparencyLogEntry(ctx, domain.PublicTransparencyLogEntry{}, "")},
		{"evidence summary", repositories.Future.InsertEvidenceSummary(ctx, domain.EvidenceSummary{})},
		{"evidence graph snapshot", repositories.Future.InsertEvidenceGraphSnapshot(ctx, domain.EvidenceGraphSnapshot{})},
		{"SaaS edition profile", repositories.Future.InsertSaaSEditionProfile(ctx, domain.SaaSEditionProfile{})},
		{"marketplace collector", repositories.Future.InsertMarketplaceCollector(ctx, domain.MarketplaceCollector{})},
		{"PDF report package", repositories.Future.InsertPDFReportPackage(ctx, domain.PDFReportPackage{})},
		{"questionnaire draft", repositories.Future.InsertQuestionnaireDraft(ctx, domain.QuestionnaireDraft{})},
		{"anomaly report", repositories.Future.InsertAnomalyReport(ctx, domain.AnomalyReport{})},
		{"signing operation", repositories.Future.InsertSigningOperation(ctx, domain.Signature{}, domain.SigningOperation{})},
		{"verification", repositories.Verification.InsertVerificationResult(ctx, domain.VerificationResult{})},
		{"policy evaluation", repositories.Verification.InsertPolicyEvaluation(ctx, domain.PolicyEvaluation{})},
		{"commercial collector", repositories.Enterprise.InsertCommercialCollectorDefinition(ctx, domain.CommercialCollectorDefinition{})},
		{"questionnaire template", repositories.Enterprise.InsertQuestionnaireTemplate(ctx, domain.QuestionnaireTemplate{})},
		{"questionnaire answer library", repositories.Enterprise.InsertQuestionnaireAnswerLibraryEntry(ctx, domain.QuestionnaireAnswerLibraryEntry{})},
		{"questionnaire package", repositories.Enterprise.InsertQuestionnairePackage(ctx, domain.QuestionnairePackage{})},
	}
	for _, check := range checks {
		if !errors.Is(check.err, app.ErrValidation) {
			t.Errorf("%s err=%v, want validation", check.name, check.err)
		}
	}
	if _, err := repositories.Audit.Append(ctx, domain.AuditChainEntry{}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("invalid audit err=%v, want validation", err)
	}
	missingReferenceChecks := []struct {
		name string
		err  error
		want error
	}{
		{"release state", repositories.ReleaseCatalog.UpdateReleaseState(ctx, domain.Release{ID: "missing-release", TenantID: "ten_repository_a", ProductID: "prod_repository_a", State: "frozen"}, "draft"), app.ErrConflict},
		{"candidate insert", repositories.ReleaseCatalog.InsertReleaseCandidate(ctx, domain.ReleaseCandidate{ID: "missing-candidate", TenantID: "ten_repository_a", ReleaseID: "missing-release", Name: "Missing", State: "open", SnapshotHash: "sha256:missing", SchemaVersion: domain.ReleaseCandidateSchemaVersion, CreatedAt: now}), app.ErrNotFound},
		{"candidate state", repositories.ReleaseCatalog.UpdateReleaseCandidateState(ctx, domain.ReleaseCandidate{ID: "missing-candidate", TenantID: "ten_repository_a", ReleaseID: "missing-release", State: "promoted"}, "open"), app.ErrConflict},
		{"evidence links", repositories.Evidence.UpdateEvidenceLinks(ctx, domain.EvidenceItem{ID: "missing-evidence", TenantID: "ten_repository_a"}), app.ErrNotFound},
		{"SBOM evidence", repositories.Evidence.InsertSBOM(ctx, domain.SBOM{ID: "missing-sbom", TenantID: "ten_repository_a", EvidenceID: "missing-evidence", Format: "cyclonedx", CreatedAt: now}), app.ErrNotFound},
		{"scan evidence", repositories.Evidence.InsertVulnerabilityScan(ctx, domain.VulnerabilityScan{ID: "missing-scan", TenantID: "ten_repository_a", EvidenceID: "missing-evidence", Scanner: "test", TargetRef: "target", CreatedAt: now}), app.ErrNotFound},
		{"OpenAPI product", repositories.Evidence.InsertOpenAPIContract(ctx, domain.OpenAPIContract{ID: "missing-contract", TenantID: "ten_repository_a", ProductID: "missing-product", EvidenceID: "missing-evidence", Version: "v1", Hash: "sha256:missing", CreatedAt: now}), app.ErrNotFound},
		{"VEX evidence", repositories.Evidence.InsertVEXDocument(ctx, domain.VEXDocument{ID: "missing-vex", TenantID: "ten_repository_a", EvidenceID: "missing-evidence", ReleaseID: "missing-release", Format: "openvex", SchemaVersion: domain.VEXDocumentSchemaVersion, CreatedAt: now}), app.ErrNotFound},
		{"VEX report", repositories.Evidence.InsertVEXImportReport(ctx, domain.VEXImportReport{ID: "missing-vex-report", TenantID: "ten_repository_a", VEXDocumentID: "missing-vex", EvidenceID: "missing-evidence", ParserVersion: app.ParserVersionOpenVEXJSON, Status: "parsed", SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now}), app.ErrNotFound},
		{"Cosign signature", repositories.Integrity.InsertCosignVerification(ctx, domain.CosignVerification{ID: "cosign_missing_signature", TenantID: "ten_repository_a", ArtifactID: "missing-artifact", ArtifactSignatureID: "missing-signature", SubjectDigest: "sha256:missing", Result: "limited", Checks: []domain.VerifyCheck{}, SchemaVersion: domain.CosignVerificationSchemaVersion, CreatedAt: now}), app.ErrNotFound},
		{"transparency checkpoint batch", repositories.Integrity.InsertTransparencyCheckpoint(ctx, domain.TransparencyCheckpoint{ID: "checkpoint_missing_batch", TenantID: "ten_repository_a", BatchID: "missing-batch", Provider: "rfc3161", ExternalID: "checkpoint", TimestampHash: "sha256:checkpoint", State: "recorded", SchemaVersion: domain.TransparencyCheckpointVersion, CreatedAt: now}), app.ErrNotFound},
		{"marketplace collector signature", repositories.Future.InsertMarketplaceCollector(ctx, domain.MarketplaceCollector{ID: "marketplace_missing_signature", TenantID: "ten_repository_a", Name: "Missing signature", Provider: "scanner", Version: "1.0.0", Publisher: "vendor", ManifestHash: "sha256:marketplace", SignatureID: "missing-signature", State: "registered", SchemaVersion: domain.MarketplaceCollectorVersion, CreatedAt: now}), app.ErrNotFound},
		{"marketplace collector SBOM", repositories.Future.InsertMarketplaceCollector(ctx, domain.MarketplaceCollector{ID: "marketplace_missing_sbom", TenantID: "ten_repository_a", Name: "Missing SBOM", Provider: "scanner", Version: "1.0.0", Publisher: "vendor", ManifestHash: "sha256:marketplace", SBOMID: "missing-sbom", State: "registered", SchemaVersion: domain.MarketplaceCollectorVersion, CreatedAt: now}), app.ErrNotFound},
		{"marketplace collector scan", repositories.Future.InsertMarketplaceCollector(ctx, domain.MarketplaceCollector{ID: "marketplace_missing_scan", TenantID: "ten_repository_a", Name: "Missing scan", Provider: "scanner", Version: "1.0.0", Publisher: "vendor", ManifestHash: "sha256:marketplace", ScanID: "missing-scan", State: "registered", SchemaVersion: domain.MarketplaceCollectorVersion, CreatedAt: now}), app.ErrNotFound},
		{"PDF report product", repositories.Future.InsertPDFReportPackage(ctx, domain.PDFReportPackage{ID: "pdf_missing_product", TenantID: "ten_repository_a", ReportType: "release_readiness", ProductID: "missing-product", Title: "Missing product", PayloadHash: "sha256:report", PayloadSize: 1, SchemaVersion: domain.PDFReportPackageVersion, CreatedAt: now}), app.ErrNotFound},
		{"PDF report release", repositories.Future.InsertPDFReportPackage(ctx, domain.PDFReportPackage{ID: "pdf_missing_release", TenantID: "ten_repository_a", ReportType: "release_readiness", ReleaseID: "missing-release", Title: "Missing release", PayloadHash: "sha256:report", PayloadSize: 1, SchemaVersion: domain.PDFReportPackageVersion, CreatedAt: now}), app.ErrNotFound},
		{"questionnaire draft template", repositories.Future.InsertQuestionnaireDraft(ctx, domain.QuestionnaireDraft{ID: "draft_missing_template", TenantID: "ten_repository_a", TemplateID: "missing-template", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "No evidence."}}, ManifestHash: "sha256:draft", SchemaVersion: domain.QuestionnaireDraftVersion, CreatedAt: now}), app.ErrNotFound},
		{"anomaly report subject", repositories.Future.InsertAnomalyReport(ctx, domain.AnomalyReport{ID: "anomaly_missing_subject", TenantID: "ten_repository_a", SubjectType: "release", SubjectID: "missing-release", Result: "clear", Signals: []domain.AnomalySignal{}, Assumptions: []string{"stored evidence"}, Limitations: []string{"evidence anomalies only"}, SchemaVersion: domain.AnomalyReportVersion, CreatedAt: now}), app.ErrNotFound},
		{"signing operation provider", repositories.Future.InsertSigningOperation(ctx, domain.Signature{ID: "provider_signature_missing", TenantID: "ten_repository_a", SubjectType: "release", SubjectID: "missing-release", KeyID: "missing-provider", Algorithm: "external-aws_kms", Value: "receipt", CreatedAt: now}, domain.SigningOperation{ID: "signing_operation_missing", TenantID: "ten_repository_a", ProviderID: "missing-provider", SubjectType: "release", SubjectID: "missing-release", PayloadHash: "sha256:" + strings.Repeat("c", 64), SignatureRef: "provider_signature_missing", Result: "passed", Checks: []domain.VerifyCheck{{Name: "provider_active", Result: "passed"}}, SchemaVersion: domain.SigningOperationVersion, CreatedAt: now}), app.ErrNotFound},
		{"policy evaluation release", repositories.Verification.InsertPolicyEvaluation(ctx, domain.PolicyEvaluation{ID: "policy_missing_release", TenantID: "ten_repository_a", ReleaseID: "missing-release", Result: "passed", PolicySet: domain.PolicySetVersion, CreatedAt: now}), app.ErrNotFound},
	}
	for _, check := range missingReferenceChecks {
		if !errors.Is(check.err, check.want) {
			t.Errorf("%s err=%v, want %v", check.name, check.err, check.want)
		}
	}
	releaseA := domain.Release{ID: "rel_repository_a", TenantID: "ten_repository_a", ProductID: "prod_repository_a", Version: "1.0.0", State: "draft", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertRelease(ctx, releaseA); err != nil {
		t.Fatalf("insert tenant A release: %v", err)
	}
	artifactA := domain.Artifact{ID: "art_repository_a", TenantID: "ten_repository_a", Name: "A artifact", MediaType: "application/octet-stream", Digest: "sha256:artifact-a", Size: 1, CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertArtifact(ctx, artifactA); err != nil {
		t.Fatalf("insert tenant A artifact: %v", err)
	}
	evidenceA := domain.EvidenceItem{ID: "evi_repository_a", TenantID: "ten_repository_a", ProductID: "prod_repository_a", ReleaseID: releaseA.ID, Type: "note", Title: "A evidence", SourceSystem: "test", ObservedAt: now, SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadHash: "sha256:evidence-a", CanonicalHash: "sha256:evidence-a", Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "untrusted", VerificationStatus: "not_verified", CreatedAt: now}
	if err := repositories.Evidence.InsertEvidence(ctx, evidenceA); err != nil {
		t.Fatalf("insert tenant A evidence: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO questionnaire_templates (id, tenant_id, name, version, questions, schema_version, created_at) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)`, "template_repository_a", "ten_repository_a", "A template", "1", `[{"id":"q1","prompt":"Is evidence available?"}]`, domain.QuestionnaireTemplateVersion, now); err != nil {
		t.Fatalf("seed tenant A questionnaire template: %v", err)
	}
	signingKeyA := domain.SigningKey{ID: "sigkey_repository_a", TenantID: "ten_repository_a", KID: "a-key", Algorithm: "Ed25519", Status: "active", PublicKey: "public-key", CreatedAt: now}
	if err := repositories.Signatures.InsertSigningKey(ctx, signingKeyA); err != nil {
		t.Fatalf("insert tenant A signing key: %v", err)
	}
	if err := repositories.Signatures.InsertSignature(ctx, domain.Signature{ID: "sig_repository_a", TenantID: "ten_repository_a", SubjectType: "evidence_item", SubjectID: evidenceA.ID, KeyID: signingKeyA.ID, Algorithm: "Ed25519", Value: "signature", CreatedAt: now}); err != nil {
		t.Fatalf("insert tenant A signature: %v", err)
	}
	if err := repositories.Integrity.InsertSigningProvider(ctx, domain.SigningProvider{ID: "provider_repository_a", TenantID: "ten_repository_a", Name: "A KMS", Type: "aws_kms", Status: "active", KeyRef: "arn:aws:kms:a", Encrypted: true, SchemaVersion: domain.SigningProviderSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert tenant A signing provider: %v", err)
	}
	if err := repositories.SupplyChain.InsertArtifactSignature(ctx, domain.ArtifactSignature{ID: "artsig_repository_a", TenantID: "ten_repository_a", ArtifactID: artifactA.ID, SubjectDigest: artifactA.Digest, Algorithm: "cosign", Signature: "signature", VerificationStatus: "recorded", SchemaVersion: domain.ArtifactSignatureSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert tenant A artifact signature: %v", err)
	}
	merkleBatchA := domain.MerkleBatch{ID: "merkle_repository_a", TenantID: "ten_repository_a", FromSequence: 1, ToSequence: 1, EntryCount: 1, LeafHashes: []string{"sha256:leaf-a"}, RootHash: "sha256:root-a", SchemaVersion: domain.MerkleBatchSchemaVersion, CreatedAt: now}
	if err := repositories.Integrity.InsertMerkleBatch(ctx, merkleBatchA); err != nil {
		t.Fatalf("insert tenant A Merkle batch: %v", err)
	}
	organizationA := domain.Organization{ID: "org_repository_a", TenantID: "ten_repository_a", Name: "A organization", Slug: "a-organization", Status: "active", SchemaVersion: domain.OrganizationSchemaVersion, CreatedAt: now}
	if err := repositories.Identity.InsertOrganization(ctx, organizationA); err != nil {
		t.Fatalf("insert tenant A organization: %v", err)
	}
	userA := domain.HumanUser{ID: "usr_repository_a", TenantID: "ten_repository_a", OrganizationID: organizationA.ID, Email: "a@example.test", DisplayName: "A user", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: now}
	if err := repositories.Identity.InsertHumanUser(ctx, userA); err != nil {
		t.Fatalf("insert tenant A user: %v", err)
	}
	providerA := domain.SSOProvider{ID: "sso_repository_a", TenantID: "ten_repository_a", Name: "A OIDC", Type: "oidc", Issuer: "https://a-idp.example.test", ClientID: "a-client", Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: now}
	if err := repositories.Identity.InsertSSOProvider(ctx, providerA); err != nil {
		t.Fatalf("insert tenant A provider: %v", err)
	}
	frameworkA := domain.ControlFramework{ID: "fw_repository_a", TenantID: "ten_repository_a", Name: "A controls", Slug: "a-controls", Version: "1", Status: "active", SchemaVersion: domain.ControlFrameworkSchemaVersion, CreatedAt: now}
	if err := repositories.Controls.InsertControlFramework(ctx, frameworkA); err != nil {
		t.Fatalf("insert tenant A control framework: %v", err)
	}
	controlA := domain.SecurityControl{ID: "ctrl_repository_a", TenantID: "ten_repository_a", FrameworkID: frameworkA.ID, Code: "CTRL-A", Title: "A control", Objective: "Record A evidence", SchemaVersion: domain.SecurityControlSchemaVersion, CreatedAt: now}
	if err := repositories.Controls.InsertSecurityControl(ctx, controlA); err != nil {
		t.Fatalf("insert tenant A security control: %v", err)
	}
	waiverA := domain.Waiver{ID: "wv_repository_a", TenantID: "ten_repository_a", ScopeType: "release", ScopeID: releaseA.ID, ControlID: controlA.ID, Owner: "security", Risk: "accepted temporarily", Reason: "A waiver", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.WaiverSchemaVersion, CreatedAt: now}
	if err := repositories.Governance.InsertWaiver(ctx, waiverA); err != nil {
		t.Fatalf("insert tenant A waiver: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO customer_security_packages (
			id, tenant_id, product_id, redaction_profile_id, title, state, manifest,
			manifest_hash, expires_at, schema_version, created_at
		)
		VALUES ('pkg_repository_a', 'ten_repository_a', 'prod_repository_a', 'redaction_a', 'A package', 'generated', '{}'::jsonb, 'sha256:package-a', $1, $2, $3)
	`, now.Add(time.Hour), domain.CustomerPackageSchemaVersion, now); err != nil {
		t.Fatalf("seed tenant A customer package: %v", err)
	}
	foreignReferenceChecks := []struct {
		name string
		err  error
	}{
		{"human user organization", repositories.Identity.InsertHumanUser(ctx, domain.HumanUser{ID: "usr_repository_b", TenantID: "ten_repository_b", OrganizationID: organizationA.ID, Email: "b@example.test", DisplayName: "B user", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: now})},
		{"role binding subject", repositories.Identity.InsertRoleBinding(ctx, domain.RoleBinding{ID: "rbac_repository_b", TenantID: "ten_repository_b", SubjectType: "user", SubjectID: userA.ID, Role: "security_engineer", ResourceType: "tenant", ResourceID: "ten_repository_b", SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now})},
		{"identity link", repositories.Identity.InsertUserIdentityLink(ctx, domain.UserIdentityLink{ID: "link_repository_b", TenantID: "ten_repository_b", UserID: userA.ID, ProviderID: providerA.ID, Subject: "b-subject", Email: "b@example.test", Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: now})},
		{"provider verification", repositories.Identity.InsertProviderVerification(ctx, domain.ProviderVerification{ID: "pvr_repository_b", TenantID: "ten_repository_b", ProviderType: "oidc", ProviderID: providerA.ID, Subject: "b-subject", Result: "failed", SchemaVersion: domain.ProviderVerificationVersion, CreatedAt: now})},
		{"SSO session", repositories.Identity.InsertSSOSession(ctx, domain.SSOSession{ID: "sess_repository_b", TenantID: "ten_repository_b", UserID: userA.ID, ProviderID: providerA.ID, Prefix: "evysso_b", Hash: "hash-b", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: now})},
		{"customer portal access", repositories.Identity.InsertCustomerPortalAccess(ctx, domain.CustomerPortalAccess{ID: "cpa_repository_b", TenantID: "ten_repository_b", PackageID: "pkg_repository_a", CustomerName: "B customer", Prefix: "evycp_b", Hash: "portal-hash-b", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.CustomerPortalAccessVersion, CreatedAt: now})},
		{"security control framework", repositories.Controls.InsertSecurityControl(ctx, domain.SecurityControl{ID: "ctrl_repository_b", TenantID: "ten_repository_b", FrameworkID: frameworkA.ID, Code: "CTRL-B", Title: "B control", Objective: "Record B evidence", SchemaVersion: domain.SecurityControlSchemaVersion, CreatedAt: now})},
		{"control evidence", repositories.Controls.InsertControlEvidence(ctx, domain.ControlEvidence{ID: "ce_repository_b", TenantID: "ten_repository_b", ControlID: controlA.ID, EvidenceType: "sbom", SubjectType: "evidence", SubjectID: evidenceA.ID, Confidence: "high", SchemaVersion: domain.ControlEvidenceSchemaVersion, CreatedAt: now})},
		{"waiver control", repositories.Governance.InsertWaiver(ctx, domain.Waiver{ID: "wv_repository_b", TenantID: "ten_repository_b", ScopeType: "release", ScopeID: "rel_repository_b", ControlID: controlA.ID, Owner: "security", Risk: "accepted temporarily", Reason: "B waiver", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.WaiverSchemaVersion, CreatedAt: now})},
		{"waiver approval", repositories.Governance.ApproveWaiver(ctx, domain.Waiver{ID: waiverA.ID, TenantID: "ten_repository_b", Approved: true, ApprovedBy: "key_repository_b", ApprovedAt: &now, ExpiresAt: now.Add(time.Hour)})},
		{"approval evidence", repositories.Governance.InsertApprovalRecord(ctx, domain.ApprovalRecord{ID: "apr_repository_b", TenantID: "ten_repository_b", SubjectType: "release", SubjectID: "rel_repository_b", Decision: "approved", Reason: "B approval", ApproverID: "key_repository_b", EvidenceID: evidenceA.ID, SchemaVersion: domain.ApprovalRecordSchemaVersion, CreatedAt: now})},
		{"exception release", repositories.Decisions.InsertException(ctx, domain.Exception{ID: "ex_repository_b", TenantID: "ten_repository_b", ReleaseID: releaseA.ID, Reason: "B exception", Owner: "security", ExpiresAt: now.Add(time.Hour), CreatedAt: now})},
		{"legal hold release", repositories.Governance.InsertLegalHold(ctx, domain.LegalHold{ID: "lh_repository_b", TenantID: "ten_repository_b", ScopeType: "release", ScopeID: releaseA.ID, Reason: "B hold", Owner: "legal", SchemaVersion: domain.LegalHoldSchemaVersion, CreatedAt: now})},
		{"retention override evidence", repositories.Governance.InsertRetentionOverride(ctx, domain.RetentionOverride{ID: "ro_repository_b", TenantID: "ten_repository_b", ScopeType: "evidence", ScopeID: evidenceA.ID, RetentionUntil: now.Add(time.Hour), Reason: "B override", Owner: "security", SchemaVersion: domain.RetentionOverrideSchemaVersion, CreatedAt: now})},
		{"build run project", repositories.Builds.InsertBuildRun(ctx, domain.BuildRun{ID: "build_repository_b", TenantID: "ten_repository_b", ProjectID: "proj_repository_b", ReleaseID: releaseA.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: now, SchemaVersion: domain.BuildRunSchemaVersion, CreatedAt: now})},
		{"candidate release", repositories.ReleaseCatalog.InsertReleaseCandidate(ctx, domain.ReleaseCandidate{ID: "rc_repository_b", TenantID: "ten_repository_b", ReleaseID: releaseA.ID, Name: "B candidate", State: "open", SnapshotHash: "sha256:candidate-b", SchemaVersion: domain.ReleaseCandidateSchemaVersion, CreatedAt: now})},
		{"evidence link product", repositories.Evidence.UpdateEvidenceLinks(ctx, domain.EvidenceItem{ID: evidenceA.ID, TenantID: "ten_repository_b", ProductID: "prod_repository_a"})},
		{"SBOM evidence", repositories.Evidence.InsertSBOM(ctx, domain.SBOM{ID: "sbom_repository_b", TenantID: "ten_repository_b", EvidenceID: evidenceA.ID, ReleaseID: releaseA.ID, ArtifactID: artifactA.ID, Format: "cyclonedx", CreatedAt: now})},
		{"scan evidence", repositories.Evidence.InsertVulnerabilityScan(ctx, domain.VulnerabilityScan{ID: "scan_repository_b", TenantID: "ten_repository_b", EvidenceID: evidenceA.ID, ReleaseID: releaseA.ID, Scanner: "test", TargetRef: "target", CreatedAt: now})},
		{"OpenAPI product", repositories.Evidence.InsertOpenAPIContract(ctx, domain.OpenAPIContract{ID: "oas_repository_b", TenantID: "ten_repository_b", ProductID: "prod_repository_a", ReleaseID: releaseA.ID, Version: "v1", Hash: "sha256:openapi-b", EvidenceID: evidenceA.ID, CreatedAt: now})},
		{"VEX evidence", repositories.Evidence.InsertVEXDocument(ctx, domain.VEXDocument{ID: "vex_repository_b", TenantID: "ten_repository_b", EvidenceID: evidenceA.ID, ReleaseID: releaseA.ID, ArtifactID: artifactA.ID, Format: "openvex", SchemaVersion: domain.VEXDocumentSchemaVersion, CreatedAt: now})},
		{"Cosign signature", repositories.Integrity.InsertCosignVerification(ctx, domain.CosignVerification{ID: "cosign_repository_b", TenantID: "ten_repository_b", ArtifactID: artifactA.ID, ArtifactSignatureID: "artsig_repository_a", SubjectDigest: artifactA.Digest, Result: "limited", Checks: []domain.VerifyCheck{}, SchemaVersion: domain.CosignVerificationSchemaVersion, CreatedAt: now})},
		{"transparency checkpoint batch", repositories.Integrity.InsertTransparencyCheckpoint(ctx, domain.TransparencyCheckpoint{ID: "checkpoint_repository_b", TenantID: "ten_repository_b", BatchID: merkleBatchA.ID, Provider: "rfc3161", ExternalID: "checkpoint", TimestampHash: "sha256:checkpoint-b", State: "recorded", SchemaVersion: domain.TransparencyCheckpointVersion, CreatedAt: now})},
		{"marketplace collector signature", repositories.Future.InsertMarketplaceCollector(ctx, domain.MarketplaceCollector{ID: "marketplace_repository_b", TenantID: "ten_repository_b", Name: "Foreign signature", Provider: "scanner", Version: "1.0.0", Publisher: "vendor", ManifestHash: "sha256:marketplace-b", SignatureID: "sig_repository_a", State: "registered", SchemaVersion: domain.MarketplaceCollectorVersion, CreatedAt: now})},
		{"PDF report product", repositories.Future.InsertPDFReportPackage(ctx, domain.PDFReportPackage{ID: "pdf_repository_b", TenantID: "ten_repository_b", ReportType: "release_readiness", ProductID: "prod_repository_a", Title: "Foreign product", PayloadHash: "sha256:report-b", PayloadSize: 1, SchemaVersion: domain.PDFReportPackageVersion, CreatedAt: now})},
		{"questionnaire draft template", repositories.Future.InsertQuestionnaireDraft(ctx, domain.QuestionnaireDraft{ID: "draft_repository_b", TenantID: "ten_repository_b", TemplateID: "template_repository_a", Responses: []domain.QuestionnaireResponse{{QuestionID: "q1", Answer: "Foreign template."}}, ManifestHash: "sha256:draft-b", SchemaVersion: domain.QuestionnaireDraftVersion, CreatedAt: now})},
		{"anomaly report subject", repositories.Future.InsertAnomalyReport(ctx, domain.AnomalyReport{ID: "anomaly_repository_b", TenantID: "ten_repository_b", SubjectType: "release", SubjectID: releaseA.ID, Result: "clear", Signals: []domain.AnomalySignal{}, Assumptions: []string{"stored evidence"}, Limitations: []string{"evidence anomalies only"}, SchemaVersion: domain.AnomalyReportVersion, CreatedAt: now})},
		{"signing operation provider", repositories.Future.InsertSigningOperation(ctx, domain.Signature{ID: "provider_signature_repository_b", TenantID: "ten_repository_b", SubjectType: "release", SubjectID: "rel_repository_b", KeyID: "provider_repository_a", Algorithm: "external-aws_kms", Value: "receipt", CreatedAt: now}, domain.SigningOperation{ID: "signing_operation_repository_b", TenantID: "ten_repository_b", ProviderID: "provider_repository_a", SubjectType: "release", SubjectID: "rel_repository_b", PayloadHash: "sha256:" + strings.Repeat("d", 64), SignatureRef: "provider_signature_repository_b", Result: "passed", Checks: []domain.VerifyCheck{{Name: "provider_active", Result: "passed"}}, SchemaVersion: domain.SigningOperationVersion, CreatedAt: now})},
		{"decision scan", repositories.Decisions.SupersedeAndInsert(ctx, domain.VulnerabilityDecision{ID: "dec_repository_b", TenantID: "ten_repository_b", FindingID: "finding-b", ScanID: "scan_repository_b", ReleaseID: releaseA.ID, Vulnerability: "CVE-2026-0001", Status: "not_affected", Justification: "test", Source: "test", SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: now}, nil)},
		{"policy evaluation release", repositories.Verification.InsertPolicyEvaluation(ctx, domain.PolicyEvaluation{ID: "policy_repository_b", TenantID: "ten_repository_b", ReleaseID: releaseA.ID, Result: "passed", PolicySet: domain.PolicySetVersion, CreatedAt: now})},
	}
	for _, check := range foreignReferenceChecks {
		if !errors.Is(check.err, app.ErrNotFound) {
			t.Errorf("%s err=%v, want not found", check.name, check.err)
		}
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

func TestRepositoriesRejectStaleStateTransitionsAndRepeatedSupersession(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	repositories := postgresrepositories.New(tx)
	now := time.Now().UTC().Round(0)
	tenant := domain.Tenant{ID: "ten_repository_conflicts", Name: "Conflicts", CreatedAt: now}
	if err := repositories.Identity.InsertTenant(ctx, tenant); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	product := domain.Product{ID: "prod_repository_conflicts", TenantID: tenant.ID, Name: "Conflicts API", Slug: "conflicts-api", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	release := domain.Release{ID: "rel_repository_conflicts", TenantID: tenant.ID, ProductID: product.ID, Version: "1.0.0", State: "draft", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertRelease(ctx, release); err != nil {
		t.Fatalf("insert release: %v", err)
	}
	project := domain.Project{ID: "proj_repository_conflicts", TenantID: tenant.ID, ProductID: product.ID, Name: "Conflicts project", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertProject(ctx, project); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	build := domain.BuildRun{ID: "build_repository_conflicts", TenantID: tenant.ID, ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: now, SchemaVersion: domain.BuildRunSchemaVersion, CreatedAt: now}
	if err := repositories.Builds.InsertBuildRun(ctx, build); err != nil {
		t.Fatalf("insert build: %v", err)
	}
	badBuild := build
	badBuild.ID = "build_repository_bad"
	badBuild.SourceIdentity = map[string]any{"not_json": math.NaN()}
	if err := repositories.Builds.InsertBuildRun(ctx, badBuild); err == nil {
		t.Fatal("expected build source identity encoding failure")
	}
	if err := repositories.ReleaseCatalog.UpdateReleaseState(ctx, domain.Release{ID: release.ID, TenantID: tenant.ID, ProductID: product.ID, State: "approved"}, "frozen"); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale release transition err=%v, want conflict", err)
	}
	candidate := domain.ReleaseCandidate{ID: "rc_repository_conflicts", TenantID: tenant.ID, ReleaseID: release.ID, Name: "Conflicts candidate", State: "open", SnapshotHash: "sha256:candidate", SchemaVersion: domain.ReleaseCandidateSchemaVersion, CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertReleaseCandidate(ctx, candidate); err != nil {
		t.Fatalf("insert candidate: %v", err)
	}
	candidate.State = "promoted"
	candidate.PromotedAt = &now
	if err := repositories.ReleaseCatalog.UpdateReleaseCandidateState(ctx, candidate, "rejected"); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale candidate transition err=%v, want conflict", err)
	}
	evidence := domain.EvidenceItem{ID: "evi_repository_conflicts", TenantID: tenant.ID, ProductID: product.ID, ReleaseID: release.ID, Type: "note", Title: "first", SourceSystem: "test", ObservedAt: now, SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadHash: "sha256:first", CanonicalHash: "sha256:first", Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "untrusted", VerificationStatus: "not_verified", CreatedAt: now}
	if err := repositories.Evidence.InsertEvidence(ctx, evidence); err != nil {
		t.Fatalf("insert first evidence: %v", err)
	}
	replacement := evidence
	replacement.ID, replacement.Title, replacement.CanonicalHash = "evi_repository_conflicts_replacement", "replacement", "sha256:replacement"
	if err := repositories.Evidence.InsertEvidence(ctx, replacement); err != nil {
		t.Fatalf("insert replacement evidence: %v", err)
	}
	evidence.SupersededBy, replacement.Supersedes = replacement.ID, evidence.ID
	if err := repositories.Evidence.RecordSupersession(ctx, evidence, replacement); err != nil {
		t.Fatalf("record supersession: %v", err)
	}
	if err := repositories.Evidence.RecordSupersession(ctx, evidence, replacement); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("repeated evidence supersession err=%v, want conflict", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback conflict test transaction: %v", err)
	}
}

func TestRepositoriesPropagateClosedTransactionFailures(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("close transaction: %v", err)
	}
	repositories := postgresrepositories.New(tx)
	now := time.Now().UTC().Round(0)
	tenantID := "ten_closed"
	release := domain.Release{ID: "rel_closed", TenantID: tenantID, ProductID: "prod_closed", Version: "1.0.0", State: "draft", CreatedAt: now}
	evidence := domain.EvidenceItem{ID: "evi_closed", TenantID: tenantID, Type: "note", Title: "Closed", SourceSystem: "test", ObservedAt: now, SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadHash: "sha256:closed", CanonicalHash: "sha256:closed", Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "untrusted", VerificationStatus: "not_verified", CreatedAt: now}
	candidate := domain.ReleaseCandidate{ID: "rc_closed", TenantID: tenantID, ReleaseID: release.ID, Name: "Closed", State: "open", SnapshotHash: "sha256:closed", SchemaVersion: domain.ReleaseCandidateSchemaVersion, CreatedAt: now}
	vex := domain.VEXDocument{ID: "vex_closed", TenantID: tenantID, EvidenceID: evidence.ID, ReleaseID: release.ID, Format: "openvex", SchemaVersion: domain.VEXDocumentSchemaVersion, CreatedAt: now}
	decision := domain.VulnerabilityDecision{ID: "dec_closed", TenantID: tenantID, FindingID: "finding_closed", ScanID: "scan_closed", ReleaseID: release.ID, Vulnerability: "CVE-2026-0001", Status: "not_affected", Justification: "test", Source: "test", SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: now}
	checks := []struct {
		name string
		run  func() error
	}{
		{"tenant", func() error {
			return repositories.Identity.InsertTenant(ctx, domain.Tenant{ID: tenantID, Name: "Closed", CreatedAt: now})
		}},
		{"API key", func() error {
			return repositories.Identity.InsertAPIKey(ctx, domain.APIKey{ID: "key_closed", TenantID: tenantID, Name: "Closed", Prefix: "evy_closed", Hash: "hash", CreatedAt: now})
		}},
		{"API key usage", func() error {
			return repositories.Identity.UpdateAPIKeyLastUsed(ctx, domain.APIKey{ID: "key_closed", TenantID: tenantID, Prefix: "evy_closed", Hash: "hash", LastUsedAt: &now})
		}},
		{"collector usage", func() error {
			return repositories.Identity.UpdateCollectorLastSeen(ctx, domain.Collector{ID: "col_closed", TenantID: tenantID, APIKeyID: "key_closed", LastSeenAt: &now})
		}},
		{"organization", func() error {
			return repositories.Identity.InsertOrganization(ctx, domain.Organization{ID: "org_closed", TenantID: tenantID, Name: "Closed", Slug: "closed", Status: "active", SchemaVersion: domain.OrganizationSchemaVersion, CreatedAt: now})
		}},
		{"human user", func() error {
			return repositories.Identity.InsertHumanUser(ctx, domain.HumanUser{ID: "usr_closed", TenantID: tenantID, Email: "closed@example.test", DisplayName: "Closed", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: now})
		}},
		{"human user deactivation", func() error {
			return repositories.Identity.DeactivateHumanUser(ctx, domain.HumanUser{ID: "usr_closed", TenantID: tenantID, Status: "deactivated", DeactivatedAt: &now})
		}},
		{"role binding", func() error {
			return repositories.Identity.InsertRoleBinding(ctx, domain.RoleBinding{ID: "rbac_closed", TenantID: tenantID, SubjectType: "user", SubjectID: "usr_closed", Role: "security_engineer", ResourceType: "tenant", ResourceID: tenantID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now})
		}},
		{"SSO provider", func() error {
			return repositories.Identity.InsertSSOProvider(ctx, domain.SSOProvider{ID: "sso_closed", TenantID: tenantID, Name: "Closed", Type: "oidc", Issuer: "https://closed.example.test", ClientID: "closed", Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: now})
		}},
		{"SSO trust material", func() error {
			return repositories.Identity.UpdateSSOProviderTrustMaterial(ctx, domain.SSOProvider{ID: "sso_closed", TenantID: tenantID, Type: "oidc", TrustMaterialUpdatedAt: &now})
		}},
		{"identity link", func() error {
			return repositories.Identity.InsertUserIdentityLink(ctx, domain.UserIdentityLink{ID: "link_closed", TenantID: tenantID, UserID: "usr_closed", ProviderID: "sso_closed", Subject: "closed", Email: "closed@example.test", Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: now})
		}},
		{"provider verification", func() error {
			return repositories.Identity.InsertProviderVerification(ctx, domain.ProviderVerification{ID: "pvr_closed", TenantID: tenantID, ProviderType: "oidc", ProviderID: "sso_closed", Subject: "closed", Result: "failed", SchemaVersion: domain.ProviderVerificationVersion, CreatedAt: now})
		}},
		{"SSO session", func() error {
			return repositories.Identity.InsertSSOSession(ctx, domain.SSOSession{ID: "sess_closed", TenantID: tenantID, UserID: "usr_closed", ProviderID: "sso_closed", Prefix: "evysso_closed", Hash: "hash", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: now})
		}},
		{"SSO session validation", func() error {
			return repositories.Identity.ValidateActiveSSOSession(ctx, domain.SSOSession{ID: "sess_closed", TenantID: tenantID, UserID: "usr_closed", ProviderID: "sso_closed", Prefix: "evysso_closed", Hash: "hash"}, now)
		}},
		{"SSO session revocation", func() error {
			return repositories.Identity.RevokeSSOSession(ctx, domain.SSOSession{ID: "sess_closed", TenantID: tenantID, UserID: "usr_closed", ProviderID: "sso_closed", Prefix: "evysso_closed", Hash: "hash", RevokedAt: &now})
		}},
		{"customer portal access", func() error {
			return repositories.Identity.InsertCustomerPortalAccess(ctx, domain.CustomerPortalAccess{ID: "cpa_closed", TenantID: tenantID, PackageID: "pkg_closed", CustomerName: "Closed", Prefix: "evycp_closed", Hash: "hash", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.CustomerPortalAccessVersion, CreatedAt: now})
		}},
		{"customer portal access update", func() error {
			access := domain.CustomerPortalAccess{ID: "cpa_closed", TenantID: tenantID, Prefix: "evycp_closed", Hash: "hash"}
			return repositories.Identity.UpdateCustomerPortalAccess(ctx, access, access)
		}},
		{"control framework", func() error {
			return repositories.Controls.InsertControlFramework(ctx, domain.ControlFramework{ID: "fw_closed", TenantID: tenantID, Name: "Closed controls", Slug: "closed-controls", Version: "1", Status: "active", SchemaVersion: domain.ControlFrameworkSchemaVersion, CreatedAt: now})
		}},
		{"security control", func() error {
			return repositories.Controls.InsertSecurityControl(ctx, domain.SecurityControl{ID: "ctrl_closed", TenantID: tenantID, FrameworkID: "fw_closed", Code: "CTRL-CLOSED", Title: "Closed", Objective: "Closed", SchemaVersion: domain.SecurityControlSchemaVersion, CreatedAt: now})
		}},
		{"control evidence", func() error {
			return repositories.Controls.InsertControlEvidence(ctx, domain.ControlEvidence{ID: "ce_closed", TenantID: tenantID, ControlID: "ctrl_closed", EvidenceType: "sbom", SubjectType: "evidence", SubjectID: evidence.ID, Confidence: "high", SchemaVersion: domain.ControlEvidenceSchemaVersion, CreatedAt: now})
		}},
		{"waiver", func() error {
			return repositories.Governance.InsertWaiver(ctx, domain.Waiver{ID: "wv_closed", TenantID: tenantID, ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "closed", Reason: "closed", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.WaiverSchemaVersion, CreatedAt: now})
		}},
		{"waiver approval", func() error {
			return repositories.Governance.ApproveWaiver(ctx, domain.Waiver{ID: "wv_closed", TenantID: tenantID, Approved: true, ApprovedBy: "key_closed", ApprovedAt: &now, ExpiresAt: now.Add(time.Hour)})
		}},
		{"approval record", func() error {
			return repositories.Governance.InsertApprovalRecord(ctx, domain.ApprovalRecord{ID: "apr_closed", TenantID: tenantID, SubjectType: "release", SubjectID: release.ID, Decision: "approved", Reason: "closed", ApproverID: "key_closed", SchemaVersion: domain.ApprovalRecordSchemaVersion, CreatedAt: now})
		}},
		{"redaction profile", func() error {
			return repositories.Governance.InsertRedactionProfile(ctx, domain.RedactionProfile{ID: "rp_closed", TenantID: tenantID, Name: "Closed", AllowedTypes: []string{"sbom"}, SchemaVersion: domain.RedactionProfileSchemaVersion, CreatedAt: now})
		}},
		{"exception", func() error {
			return repositories.Decisions.InsertException(ctx, domain.Exception{ID: "ex_closed", TenantID: tenantID, ReleaseID: release.ID, Reason: "closed", Owner: "security", ExpiresAt: now.Add(time.Hour), CreatedAt: now})
		}},
		{"exception approval", func() error {
			return repositories.Decisions.ApproveException(ctx, domain.Exception{ID: "ex_closed", TenantID: tenantID, Approved: true, ApprovedBy: "key_closed", ApprovedAt: &now, ExpiresAt: now.Add(time.Hour)})
		}},
		{"legal hold", func() error {
			return repositories.Governance.InsertLegalHold(ctx, domain.LegalHold{ID: "lh_closed", TenantID: tenantID, ScopeType: "release", ScopeID: release.ID, Reason: "closed", Owner: "legal", SchemaVersion: domain.LegalHoldSchemaVersion, CreatedAt: now})
		}},
		{"retention override", func() error {
			return repositories.Governance.InsertRetentionOverride(ctx, domain.RetentionOverride{ID: "ro_closed", TenantID: tenantID, ScopeType: "release", ScopeID: release.ID, RetentionUntil: now.Add(time.Hour), Reason: "closed", Owner: "security", SchemaVersion: domain.RetentionOverrideSchemaVersion, CreatedAt: now})
		}},
		{"build run", func() error {
			return repositories.Builds.InsertBuildRun(ctx, domain.BuildRun{ID: "build_closed", TenantID: tenantID, ProjectID: "proj_closed", ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: now, SchemaVersion: domain.BuildRunSchemaVersion, CreatedAt: now})
		}},
		{"product", func() error {
			return repositories.ReleaseCatalog.InsertProduct(ctx, domain.Product{ID: "prod_closed", TenantID: tenantID, Name: "Closed", Slug: "closed", CreatedAt: now})
		}},
		{"project", func() error {
			return repositories.ReleaseCatalog.InsertProject(ctx, domain.Project{ID: "proj_closed", TenantID: tenantID, ProductID: "prod_closed", Name: "Closed", CreatedAt: now})
		}},
		{"release", func() error { return repositories.ReleaseCatalog.InsertRelease(ctx, release) }},
		{"release state", func() error { return repositories.ReleaseCatalog.UpdateReleaseState(ctx, release, "draft") }},
		{"artifact", func() error {
			return repositories.ReleaseCatalog.InsertArtifact(ctx, domain.Artifact{ID: "art_closed", TenantID: tenantID, Name: "closed.tgz", MediaType: "application/gzip", Digest: "sha256:closed", Size: 1, CreatedAt: now})
		}},
		{"candidate", func() error { return repositories.ReleaseCatalog.InsertReleaseCandidate(ctx, candidate) }},
		{"candidate state", func() error { return repositories.ReleaseCatalog.UpdateReleaseCandidateState(ctx, candidate, "open") }},
		{"evidence links", func() error { return repositories.Evidence.UpdateEvidenceLinks(ctx, evidence) }},
		{"evidence supersession", func() error {
			replacement := evidence
			replacement.ID, evidence.SupersededBy, replacement.Supersedes = "evi_closed_replacement", replacement.ID, evidence.ID
			return repositories.Evidence.RecordSupersession(ctx, evidence, replacement)
		}},
		{"evidence", func() error { return repositories.Evidence.InsertEvidence(ctx, evidence) }},
		{"lifecycle", func() error {
			return repositories.Evidence.AppendLifecycle(ctx, domain.EvidenceLifecycleEvent{ID: "elc_closed", TenantID: tenantID, EvidenceID: evidence.ID, Action: "accepted", ActorID: "key_closed", SchemaVersion: domain.EvidenceLifecycleSchemaVersion, CreatedAt: now})
		}},
		{"SBOM", func() error {
			return repositories.Evidence.InsertSBOM(ctx, domain.SBOM{ID: "sbom_closed", TenantID: tenantID, EvidenceID: evidence.ID, Format: "cyclonedx", CreatedAt: now})
		}},
		{"scan", func() error {
			return repositories.Evidence.InsertVulnerabilityScan(ctx, domain.VulnerabilityScan{ID: "scan_closed", TenantID: tenantID, EvidenceID: evidence.ID, Scanner: "test", TargetRef: "target", CreatedAt: now})
		}},
		{"OpenAPI", func() error {
			return repositories.Evidence.InsertOpenAPIContract(ctx, domain.OpenAPIContract{ID: "oas_closed", TenantID: tenantID, ProductID: "prod_closed", EvidenceID: evidence.ID, Version: "v1", Hash: "sha256:closed", CreatedAt: now})
		}},
		{"VEX", func() error { return repositories.Evidence.InsertVEXDocument(ctx, vex) }},
		{"VEX report", func() error {
			return repositories.Evidence.InsertVEXImportReport(ctx, domain.VEXImportReport{ID: "vexrep_closed", TenantID: tenantID, VEXDocumentID: vex.ID, EvidenceID: evidence.ID, ParserVersion: app.ParserVersionOpenVEXJSON, Status: "parsed", SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now})
		}},
		{"decision", func() error { return repositories.Decisions.InsertVulnerabilityDecision(ctx, decision) }},
		{"decision supersession", func() error {
			prior := decision
			prior.ID, prior.SupersededBy = "dec_closed_prior", decision.ID
			return repositories.Decisions.SupersedeAndInsert(ctx, decision, []domain.VulnerabilityDecision{prior})
		}},
		{"audit", func() error {
			_, err := repositories.Audit.Append(ctx, domain.AuditChainEntry{ID: "ace_closed", TenantID: tenantID, EntryType: "evidence.created", SubjectType: "evidence_item", SubjectID: evidence.ID, ActorType: "api_key", ActorID: "key_closed", OccurredAt: now})
			return err
		}},
		{"idempotency", func() error {
			return repositories.Idempotency.Insert(ctx, app.IdempotencyRecordKey{TenantID: tenantID, ActorID: "key_closed", Method: "POST", Path: "/v1/evidence", IdempotencyKey: "idem_closed"}, app.IdempotencyRecord{RequestHash: "sha256:closed", Status: 201, Response: map[string]any{"id": evidence.ID}, CreatedAt: now})
		}},
		{"outbox", func() error {
			return repositories.Outbox.Enqueue(ctx, app.OutboxJob{ID: "job_closed", TenantID: tenantID, Kind: "index_evidence", SubjectType: "evidence_item", SubjectID: evidence.ID, CreatedAt: now})
		}},
		{"package", func() error {
			return repositories.Packages.InsertReleaseBundle(ctx, domain.ReleaseBundle{ID: "bundle_closed", TenantID: tenantID, ReleaseID: release.ID, State: "generated", Manifest: map[string]any{"release_id": release.ID}, ManifestHash: "sha256:closed", CreatedAt: now})
		}},
		{"signing key", func() error {
			return repositories.Signatures.InsertSigningKey(ctx, domain.SigningKey{ID: "sigkey_closed", TenantID: tenantID, KID: "closed-key", Algorithm: "Ed25519", Status: "active", PublicKey: "public", CreatedAt: now})
		}},
		{"signature", func() error {
			return repositories.Signatures.InsertSignature(ctx, domain.Signature{ID: "sig_closed", TenantID: tenantID, SubjectType: "evidence_item", SubjectID: evidence.ID, KeyID: "sigkey_closed", Algorithm: "Ed25519", Value: "signature", CreatedAt: now})
		}},
		{"verification", func() error {
			return repositories.Verification.InsertVerificationResult(ctx, domain.VerificationResult{ID: "verify_closed", TenantID: tenantID, SubjectType: "evidence_item", SubjectID: evidence.ID, Result: "limited", Checks: []domain.VerifyCheck{{Name: "closed", Result: "passed"}}, VerifiedAt: now})
		}},
	}
	for _, check := range checks {
		if err := check.run(); err == nil {
			t.Errorf("%s accepted a closed transaction", check.name)
		}
	}
}

func TestRepositoriesRejectMalformedJSONAndRollBackPartialSupersession(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	repositories := postgresrepositories.New(tx)
	now := time.Now().UTC().Round(0)
	tenant := domain.Tenant{ID: "ten_repository_rollback", Name: "Rollback", CreatedAt: now}
	if err := repositories.Identity.InsertTenant(ctx, tenant); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	product := domain.Product{ID: "prod_repository_rollback", TenantID: tenant.ID, Name: "Rollback API", Slug: "rollback-api", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	release := domain.Release{ID: "rel_repository_rollback", TenantID: tenant.ID, ProductID: product.ID, Version: "1.0.0", State: "draft", CreatedAt: now}
	if err := repositories.ReleaseCatalog.InsertRelease(ctx, release); err != nil {
		t.Fatalf("insert release: %v", err)
	}
	evidence := domain.EvidenceItem{ID: "evi_repository_rollback", TenantID: tenant.ID, ProductID: product.ID, ReleaseID: release.ID, Type: "note", Title: "Rollback evidence", SourceSystem: "test", ObservedAt: now, SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadHash: "sha256:rollback", CanonicalHash: "sha256:rollback", Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "untrusted", VerificationStatus: "not_verified", CreatedAt: now}
	if err := repositories.Evidence.InsertEvidence(ctx, evidence); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
	nonZeroPayload := evidence
	nonZeroPayload.ID, nonZeroPayload.Title, nonZeroPayload.CanonicalHash, nonZeroPayload.PayloadSize = "evi_repository_rollback_payload", "Non-zero payload", "sha256:payload", 1
	if err := repositories.Evidence.InsertEvidence(ctx, nonZeroPayload); err != nil {
		t.Fatalf("insert evidence with non-zero payload size: %v", err)
	}
	badSourceIdentity := evidence
	badSourceIdentity.ID, badSourceIdentity.SourceIdentity = "evi_repository_rollback_bad_source", map[string]any{"not_json": math.NaN()}
	if err := repositories.Evidence.InsertEvidence(ctx, badSourceIdentity); err == nil {
		t.Fatal("expected source identity JSON encoding failure")
	}
	if err := repositories.Evidence.AppendLifecycle(ctx, domain.EvidenceLifecycleEvent{ID: "elc_repository_rollback", TenantID: tenant.ID, EvidenceID: evidence.ID, Action: "accepted", Reason: "test", Details: map[string]any{"not_json": math.NaN()}, ActorID: "test", SchemaVersion: domain.EvidenceLifecycleSchemaVersion, CreatedAt: now}); err == nil {
		t.Fatal("expected lifecycle JSON encoding failure")
	}
	replacement := evidence
	replacement.ID, replacement.Title, replacement.CanonicalHash, replacement.Supersedes = "evi_repository_rollback_replacement", "Replacement", "sha256:replacement", evidence.ID
	if err := repositories.Evidence.InsertEvidence(ctx, replacement); err != nil {
		t.Fatalf("insert pre-linked replacement: %v", err)
	}
	superseded := evidence
	superseded.SupersededBy = replacement.ID
	if err := repositories.Evidence.RecordSupersession(ctx, superseded, replacement); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("partially linked evidence supersession err=%v, want conflict", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO vulnerability_scans (id, tenant_id, evidence_id, scanner, target_ref, summary, findings, created_at)
		VALUES ('scan_repository_rollback', $1, $2, 'test', 'pkg:oci/rollback', '{}'::jsonb, '[]'::jsonb, $3)
	`, tenant.ID, evidence.ID, now); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	decision := domain.VulnerabilityDecision{ID: "dec_repository_rollback", TenantID: tenant.ID, FindingID: "finding_rollback", ScanID: "scan_repository_rollback", ReleaseID: release.ID, Vulnerability: "CVE-2026-0001", Status: "not_affected", Justification: "test", Source: "test", SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: now}
	if err := repositories.Decisions.SupersedeAndInsert(ctx, decision, []domain.VulnerabilityDecision{{ID: "dec_repository_missing", TenantID: tenant.ID, SupersededBy: decision.ID}}); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("missing superseded decision err=%v, want conflict", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback partial mutation transaction: %v", err)
	}
	var persisted int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM evidence_items WHERE tenant_id = $1`, tenant.ID).Scan(&persisted); err != nil {
		t.Fatalf("count rolled-back evidence: %v", err)
	}
	if persisted != 0 {
		t.Fatalf("partial transaction persisted %d evidence records", persisted)
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
