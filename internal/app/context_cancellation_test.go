package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestLedgerOperationsHonorCanceledContextBeforeWork(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor := domain.Actor{TenantID: "ten_ctx", KeyID: "key_ctx", Scopes: []string{"*"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	checks := []struct {
		name string
		run  func() error
	}{
		{"BootstrapTenant", func() error {
			_, _, _, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
			return err
		}},
		{"Authenticate", func() error { _, err := ledger.Authenticate(ctx, "secret"); return err }},
		{"CreateAPIKey", func() error { _, _, err := ledger.CreateAPIKey(ctx, actor, "key", []string{"*"}, nil); return err }},
		{"ListAPIKeys", func() error { _, err := ledger.ListAPIKeys(ctx, actor); return err }},
		{"CreateProduct", func() error { _, err := ledger.CreateProduct(ctx, actor, "Product", "product"); return err }},
		{"ListProducts", func() error { _, err := ledger.ListProducts(ctx, actor); return err }},
		{"CreateProject", func() error { _, err := ledger.CreateProject(ctx, actor, "prod", "api"); return err }},
		{"CreateRelease", func() error { _, err := ledger.CreateRelease(ctx, actor, "prod", "1.0.0"); return err }},
		{"GetRelease", func() error { _, err := ledger.GetRelease(ctx, actor, "rel"); return err }},
		{"FreezeRelease", func() error { _, err := ledger.FreezeRelease(ctx, actor, "rel"); return err }},
		{"ApproveRelease", func() error { _, err := ledger.ApproveRelease(ctx, actor, "rel"); return err }},
		{"RegisterArtifact", func() error {
			_, err := ledger.RegisterArtifact(ctx, actor, "artifact", "application/octet-stream", sampleDigest("artifact"), 1)
			return err
		}},
		{"CreateEvidence", func() error {
			_, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{Type: "build", Title: "Build"})
			return err
		}},
		{"GetEvidence", func() error { _, err := ledger.GetEvidence(ctx, actor, "ev"); return err }},
		{"ListEvidence", func() error { _, err := ledger.ListEvidence(ctx, actor, "", ""); return err }},
		{"SupersedeEvidence", func() error { _, err := ledger.SupersedeEvidence(ctx, actor, "ev", "ev2", "reason"); return err }},
		{"LinkEvidence", func() error { _, err := ledger.LinkEvidence(ctx, actor, "ev", "release", "rel"); return err }},
		{"UploadSBOM", func() error { _, err := ledger.UploadSBOM(ctx, actor, "rel", "art", []byte(`{}`)); return err }},
		{"UploadVulnerabilityScan", func() error { _, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{}`)); return err }},
		{"UploadOpenAPIContract", func() error {
			_, err := ledger.UploadOpenAPIContract(ctx, actor, "prod", "rel", "v1", []byte(`{}`))
			return err
		}},
		{"EvaluateRelease", func() error { _, err := ledger.EvaluateRelease(ctx, actor, "rel"); return err }},
		{"CreateReleaseBundle", func() error { _, err := ledger.CreateReleaseBundle(ctx, actor, "rel"); return err }},
		{"GetReleaseBundle", func() error { _, err := ledger.GetReleaseBundle(ctx, actor, "bundle"); return err }},
		{"GetSBOM", func() error { _, err := ledger.GetSBOM(ctx, actor, "sbom"); return err }},
		{"ListSBOMComponents", func() error { _, err := ledger.ListSBOMComponents(ctx, actor, ListSBOMComponentsInput{}); return err }},
		{"GetVulnerabilityScan", func() error { _, err := ledger.GetVulnerabilityScan(ctx, actor, "scan"); return err }},
		{"GetOpenAPIContract", func() error { _, err := ledger.GetOpenAPIContract(ctx, actor, "contract"); return err }},
		{"VerifySubject", func() error { _, err := ledger.VerifySubject(ctx, actor, "audit_chain", ""); return err }},
		{"RotateSigningKey", func() error { _, err := ledger.RotateSigningKey(ctx, actor, "reason"); return err }},
		{"ListSigningKeys", func() error { _, err := ledger.ListSigningKeys(ctx, actor); return err }},
		{"MissingEvidenceReport", func() error { _, err := ledger.MissingEvidenceReport(ctx, actor, "rel"); return err }},
		{"SearchEvidence", func() error { _, err := ledger.SearchEvidence(ctx, actor, EvidenceSearchInput{}); return err }},
		{"RecordEvidenceLifecycleEvent", func() error {
			_, err := ledger.RecordEvidenceLifecycleEvent(ctx, actor, "ev", RecordEvidenceLifecycleInput{Action: "amendment", Reason: "reason"})
			return err
		}},
		{"ListEvidenceLifecycleEvents", func() error { _, err := ledger.ListEvidenceLifecycleEvents(ctx, actor, "ev"); return err }},
		{"CreateReleaseCandidate", func() error {
			_, err := ledger.CreateReleaseCandidate(ctx, actor, CreateReleaseCandidateInput{ReleaseID: "rel", Name: "rc"})
			return err
		}},
		{"GetReleaseCandidate", func() error { _, err := ledger.GetReleaseCandidate(ctx, actor, "rc"); return err }},
		{"ListReleaseCandidates", func() error { _, err := ledger.ListReleaseCandidates(ctx, actor, "rel"); return err }},
		{"UpdateReleaseCandidateState", func() error {
			_, err := ledger.UpdateReleaseCandidateState(ctx, actor, "rc", "promoted", "reason")
			return err
		}},
		{"RegisterContainerImage", func() error {
			_, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{ArtifactID: "art", Repository: "repo", Digest: sampleDigest("image")})
			return err
		}},
		{"CreateArtifactSignature", func() error {
			_, err := ledger.CreateArtifactSignature(ctx, actor, CreateArtifactSignatureInput{ArtifactID: "art", Algorithm: "cosign", Signature: "sig"})
			return err
		}},
		{"GetArtifactSignature", func() error { _, err := ledger.GetArtifactSignature(ctx, actor, "sig"); return err }},
		{"CreateSourceRepository", func() error {
			_, err := ledger.CreateSourceRepository(ctx, actor, CreateRepositoryInput{ProjectID: "proj", Provider: "github", FullName: "owner/repo"})
			return err
		}},
		{"ListSourceRepositories", func() error { _, err := ledger.ListSourceRepositories(ctx, actor, "proj"); return err }},
		{"RecordSourceCommit", func() error {
			_, err := ledger.RecordSourceCommit(ctx, actor, RecordCommitInput{RepositoryID: "repo", SHA: "0123456789abcdef0123456789abcdef01234567"})
			return err
		}},
		{"UpsertSourceBranch", func() error {
			_, err := ledger.UpsertSourceBranch(ctx, actor, UpsertBranchInput{RepositoryID: "repo", Name: "main"})
			return err
		}},
		{"RecordPullRequest", func() error {
			_, err := ledger.RecordPullRequest(ctx, actor, RecordPullRequestInput{RepositoryID: "repo", ProviderID: "1", Title: "PR", State: "open"})
			return err
		}},
		{"UploadGitHubSourceSnapshot", func() error { _, err := ledger.UploadGitHubSourceSnapshot(ctx, actor, []byte(`{}`)); return err }},
		{"UploadGitLabSourceSnapshot", func() error { _, err := ledger.UploadGitLabSourceSnapshot(ctx, actor, []byte(`{}`)); return err }},
		{"CreateDeploymentEnvironment", func() error {
			_, err := ledger.CreateDeploymentEnvironment(ctx, actor, CreateEnvironmentInput{ProductID: "prod", Name: "prod", Kind: "production"})
			return err
		}},
		{"ListDeploymentEnvironments", func() error { _, err := ledger.ListDeploymentEnvironments(ctx, actor, "prod"); return err }},
		{"RecordDeployment", func() error {
			_, err := ledger.RecordDeployment(ctx, actor, RecordDeploymentInput{EnvironmentID: "env", ReleaseID: "rel", Status: "started"})
			return err
		}},
		{"GetDeployment", func() error { _, err := ledger.GetDeployment(ctx, actor, "dep"); return err }},
		{"ListDeployments", func() error { _, err := ledger.ListDeployments(ctx, actor, "rel", "env"); return err }},
		{"UploadVEX", func() error { _, err := ledger.UploadVEX(ctx, actor, "rel", "art", []byte(`{}`)); return err }},
		{"GetVEXDocument", func() error { _, err := ledger.GetVEXDocument(ctx, actor, "vex"); return err }},
		{"CreateVulnerabilityDecision", func() error {
			_, err := ledger.CreateVulnerabilityDecision(ctx, actor, "finding", CreateVulnerabilityDecisionInput{Status: "fixed", Justification: "fixed"})
			return err
		}},
		{"CreateException", func() error { _, err := ledger.CreateException(ctx, actor, CreateExceptionInput{}); return err }},
		{"ListExceptions", func() error { _, err := ledger.ListExceptions(ctx, actor, "rel"); return err }},
		{"ApproveException", func() error { _, err := ledger.ApproveException(ctx, actor, "ex"); return err }},
		{"ReleaseReadinessReport", func() error { _, err := ledger.ReleaseReadinessReport(ctx, actor, "rel"); return err }},
		{"CreateControlFramework", func() error {
			_, err := ledger.CreateControlFramework(ctx, actor, CreateControlFrameworkInput{Name: "Framework", Version: "1"})
			return err
		}},
		{"ListControlFrameworks", func() error { _, err := ledger.ListControlFrameworks(ctx, actor); return err }},
		{"CreateSecurityControl", func() error {
			_, err := ledger.CreateSecurityControl(ctx, actor, CreateSecurityControlInput{FrameworkID: "fw", Code: "C", Title: "Control", Objective: "Objective"})
			return err
		}},
		{"GetSecurityControl", func() error { _, err := ledger.GetSecurityControl(ctx, actor, "ctrl"); return err }},
		{"LinkControlEvidence", func() error {
			_, err := ledger.LinkControlEvidence(ctx, actor, "ctrl", LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "sbom", SubjectID: "sbom"})
			return err
		}},
		{"ListControlEvidence", func() error { _, err := ledger.ListControlEvidence(ctx, actor, "ctrl", "prod", "rel"); return err }},
		{"ControlCoverageReport", func() error {
			_, err := ledger.ControlCoverageReport(ctx, actor, ControlCoverageReportInput{FrameworkID: "fw"})
			return err
		}},
		{"CRAReadinessReport", func() error {
			_, err := ledger.CRAReadinessReport(ctx, actor, CRAReadinessReportInput{ProductID: "prod", ReleaseID: "rel"})
			return err
		}},
		{"CreateCollector", func() error {
			_, _, _, err := ledger.CreateCollector(ctx, actor, CreateCollectorInput{Name: "collector", Type: "github_actions", Version: "1"})
			return err
		}},
		{"ListCollectors", func() error { _, err := ledger.ListCollectors(ctx, actor); return err }},
		{"RecordCollectorRelease", func() error {
			_, err := ledger.RecordCollectorRelease(ctx, actor, RecordCollectorReleaseInput{CollectorID: "collector", Version: "1", ArtifactDigest: sampleDigest("collector")})
			return err
		}},
		{"CollectorHealthReport", func() error { _, err := ledger.CollectorHealthReport(ctx, actor, "collector"); return err }},
		{"CreateBuildRun", func() error {
			_, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{ProjectID: "proj", ReleaseID: "rel", Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow()})
			return err
		}},
		{"GetBuildRun", func() error { _, err := ledger.GetBuildRun(ctx, actor, "build"); return err }},
		{"UploadBuildAttestation", func() error { _, err := ledger.UploadBuildAttestation(ctx, actor, "build", []byte(`{}`)); return err }},
		{"CreateWaiver", func() error { _, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{}); return err }},
		{"ApproveWaiver", func() error { _, err := ledger.ApproveWaiver(ctx, actor, "waiver"); return err }},
		{"CreateApprovalRecord", func() error { _, err := ledger.CreateApprovalRecord(ctx, actor, CreateApprovalInput{}); return err }},
		{"CreateRedactionProfile", func() error {
			_, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "profile"})
			return err
		}},
		{"CreateCustomerSecurityPackage", func() error {
			_, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{})
			return err
		}},
		{"AccessCustomerSecurityPackage", func() error { _, err := ledger.AccessCustomerSecurityPackage(ctx, actor, "pkg"); return err }},
		{"ExportCustomerSecurityPackageArchive", func() error { _, err := ledger.ExportCustomerSecurityPackageArchive(ctx, actor, "pkg"); return err }},
		{"ExportCustomerPortalPackageArchive", func() error { _, err := ledger.ExportCustomerPortalPackageArchive(ctx, "token"); return err }},
		{"SecurityReviewPackageReport", func() error { _, err := ledger.SecurityReviewPackageReport(ctx, actor, "pkg"); return err }},
		{"CRAReadinessHTMLPackage", func() error { _, err := ledger.CRAReadinessHTMLPackage(ctx, actor, "prod", "rel"); return err }},
		{"ListControlFrameworkTemplatePacks", func() error { _, err := ledger.ListControlFrameworkTemplatePacks(ctx, actor); return err }},
		{"InstallControlFrameworkTemplatePack", func() error {
			_, err := ledger.InstallControlFrameworkTemplatePack(ctx, actor, "evydence-cra-readiness")
			return err
		}},
		{"CreateCustomReportTemplate", func() error {
			_, err := ledger.CreateCustomReportTemplate(ctx, actor, CreateReportTemplateInput{Name: "template", Version: "1", ReportType: "summary", Template: "json"})
			return err
		}},
		{"RenderCustomReport", func() error {
			_, err := ledger.RenderCustomReport(ctx, actor, RenderReportInput{TemplateID: "template", SubjectType: "release", SubjectID: "rel"})
			return err
		}},
		{"ExportEvidenceBundle", func() error { _, err := ledger.ExportEvidenceBundle(ctx, actor, "rel", nil); return err }},
		{"ImportEvidenceBundle", func() error { _, err := ledger.ImportEvidenceBundle(ctx, actor, domain.EvidenceBundle{}); return err }},
		{"CreateDSSETrustRoot", func() error {
			_, err := ledger.CreateDSSETrustRoot(ctx, actor, CreateDSSETrustRootInput{Name: "root", KeyID: "root", Algorithm: "Ed25519", PublicKey: "pub"})
			return err
		}},
		{"VerifyDSSEAttestationSignature", func() error { _, err := ledger.VerifyDSSEAttestationSignature(ctx, actor, "att"); return err }},
		{"CreateIncident", func() error {
			_, err := ledger.CreateIncident(ctx, actor, CreateIncidentInput{ProductID: "prod", Title: "incident", Severity: "high"})
			return err
		}},
		{"RecordIncidentTimelineEvent", func() error {
			_, err := ledger.RecordIncidentTimelineEvent(ctx, actor, "inc", RecordIncidentTimelineInput{EventType: "detected", Summary: "summary"})
			return err
		}},
		{"CreateIncidentWebhookReceiver", func() error {
			_, err := ledger.CreateIncidentWebhookReceiver(ctx, actor, CreateIncidentWebhookReceiverInput{IncidentID: "inc", Name: "receiver", Provider: "generic", PublicKey: "pub"})
			return err
		}},
		{"HandleIncidentWebhook", func() error { _, _, err := ledger.HandleIncidentWebhook(ctx, HandleIncidentWebhookInput{}); return err }},
		{"CreateRemediationTask", func() error {
			_, err := ledger.CreateRemediationTask(ctx, actor, CreateRemediationTaskInput{IncidentID: "inc", Title: "task", Owner: "security"})
			return err
		}},
		{"IncidentReport", func() error { _, err := ledger.IncidentReport(ctx, actor, "inc"); return err }},
		{"UploadSecurityScan", func() error { _, err := ledger.UploadSecurityScan(ctx, actor, UploadSecurityScanInput{}); return err }},
		{"UploadAPISecurityScan", func() error {
			_, err := ledger.UploadAPISecurityScan(ctx, actor, UploadSecurityScanInput{})
			return err
		}},
		{"UploadManualSecurityDocument", func() error {
			_, err := ledger.UploadManualSecurityDocument(ctx, actor, UploadManualSecurityDocumentInput{})
			return err
		}},
		{"UploadSPDXSBOM", func() error { _, err := ledger.UploadSPDXSBOM(ctx, actor, "rel", "art", []byte(`{}`)); return err }},
		{"CreateSBOMDiff", func() error { _, err := ledger.CreateSBOMDiff(ctx, actor, CreateSBOMDiffInput{}); return err }},
		{"UploadCycloneDXVEX", func() error { _, err := ledger.UploadCycloneDXVEX(ctx, actor, "rel", "art", []byte(`{}`)); return err }},
		{"RecordVulnerabilityWorkflow", func() error {
			_, err := ledger.RecordVulnerabilityWorkflow(ctx, actor, RecordVulnerabilityWorkflowInput{})
			return err
		}},
		{"VulnerabilityPostureReport", func() error { _, err := ledger.VulnerabilityPostureReport(ctx, actor, "rel"); return err }},
		{"CreateContractDiff", func() error { _, err := ledger.CreateContractDiff(ctx, actor, CreateContractDiffInput{}); return err }},
		{"CreateCustomPolicy", func() error { _, err := ledger.CreateCustomPolicy(ctx, actor, CreateCustomPolicyInput{}); return err }},
		{"EvaluateCustomPolicy", func() error { _, err := ledger.EvaluateCustomPolicy(ctx, actor, "policy", "rel"); return err }},
		{"CreateOrganization", func() error {
			_, err := ledger.CreateOrganization(ctx, actor, CreateOrganizationInput{Name: "Org", Slug: "org"})
			return err
		}},
		{"CreateUser", func() error {
			_, err := ledger.CreateUser(ctx, actor, CreateUserInput{OrganizationID: "org", Email: "user@example.test"})
			return err
		}},
		{"DeactivateUser", func() error { _, err := ledger.DeactivateUser(ctx, actor, "user"); return err }},
		{"CreateRoleBinding", func() error {
			_, err := ledger.CreateRoleBinding(ctx, actor, CreateRoleBindingInput{SubjectType: "user", SubjectID: "user", Role: "tenant_admin", ResourceType: "tenant"})
			return err
		}},
		{"ListRoleBindings", func() error { _, err := ledger.ListRoleBindings(ctx, actor); return err }},
		{"CreateSSOProvider", func() error {
			_, err := ledger.CreateSSOProvider(ctx, actor, CreateSSOProviderInput{Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client"})
			return err
		}},
		{"LinkSSOIdentity", func() error {
			_, err := ledger.LinkSSOIdentity(ctx, actor, LinkSSOIdentityInput{UserID: "user", ProviderID: "provider", Subject: "sub", Email: "user@example.test"})
			return err
		}},
		{"CreateSSOSession", func() error {
			_, _, err := ledger.CreateSSOSession(ctx, actor, CreateSSOSessionInput{UserID: "user", ProviderID: "provider", ExpiresAt: fixedNow().AddDate(0, 0, 1)})
			return err
		}},
		{"RevokeSSOSession", func() error { _, err := ledger.RevokeSSOSession(ctx, actor, "session"); return err }},
		{"InstanceAdminSnapshot", func() error { _, err := ledger.InstanceAdminSnapshot(ctx, actor); return err }},
		{"CreateLegalHold", func() error {
			_, err := ledger.CreateLegalHold(ctx, actor, CreateLegalHoldInput{ScopeType: "release", ScopeID: "rel", Reason: "review", Owner: "legal"})
			return err
		}},
		{"CreateRetentionOverride", func() error {
			_, err := ledger.CreateRetentionOverride(ctx, actor, CreateRetentionOverrideInput{ScopeType: "release", ScopeID: "rel", RetentionUntil: fixedNow().AddDate(1, 0, 0), Reason: "review", Owner: "legal"})
			return err
		}},
		{"RetentionReport", func() error { _, err := ledger.RetentionReport(ctx, actor, "release", "rel"); return err }},
		{"CreateCustomerPortalAccess", func() error {
			_, _, err := ledger.CreateCustomerPortalAccess(ctx, actor, CreateCustomerPortalAccessInput{PackageID: "pkg", CustomerName: "ACME", ExpiresAt: fixedNow().AddDate(0, 0, 1)})
			return err
		}},
		{"AccessCustomerPortalPackage", func() error { _, err := ledger.AccessCustomerPortalPackage(ctx, "token"); return err }},
		{"CreateQuestionnaireTemplate", func() error {
			_, err := ledger.CreateQuestionnaireTemplate(ctx, actor, CreateQuestionnaireTemplateInput{Name: "template", Version: "1"})
			return err
		}},
		{"CreateQuestionnairePackage", func() error {
			_, err := ledger.CreateQuestionnairePackage(ctx, actor, CreateQuestionnairePackageInput{TemplateID: "template", PackageID: "pkg", ProductID: "prod", ReleaseID: "rel"})
			return err
		}},
		{"CreateCommercialCollectorDefinition", func() error {
			_, err := ledger.CreateCommercialCollectorDefinition(ctx, actor, CreateCommercialCollectorInput{Name: "collector", Provider: "jira", Version: "1", ManifestHash: sampleDigest("collector")})
			return err
		}},
		{"ListCommercialCollectorDefinitions", func() error { _, err := ledger.ListCommercialCollectorDefinitions(ctx, actor); return err }},
		{"CreateEvidenceSummary", func() error {
			_, err := ledger.CreateEvidenceSummary(ctx, actor, CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: "rel"})
			return err
		}},
		{"CreateQuestionnaireDraft", func() error {
			_, err := ledger.CreateQuestionnaireDraft(ctx, actor, CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "prod", ReleaseID: "rel"})
			return err
		}},
		{"CreateGraphSnapshot", func() error {
			_, err := ledger.CreateGraphSnapshot(ctx, actor, CreateGraphSnapshotInput{ProductID: "prod", ReleaseID: "rel"})
			return err
		}},
		{"CreateSaaSEditionProfile", func() error {
			_, err := ledger.CreateSaaSEditionProfile(ctx, actor, CreateSaaSEditionProfileInput{Name: "profile", Region: "eu", AdminTenantID: "ten", IsolationModel: "self-hosted"})
			return err
		}},
		{"CreatePublicTransparencyLog", func() error {
			_, err := ledger.CreatePublicTransparencyLog(ctx, actor, CreatePublicTransparencyLogInput{Name: "log", Endpoint: "https://log.example.test", PublicKey: "pub"})
			return err
		}},
		{"PublishPublicTransparencyLogEntry", func() error {
			_, err := ledger.PublishPublicTransparencyLogEntry(ctx, actor, PublishPublicTransparencyLogEntryInput{LogID: "log", CheckpointID: "checkpoint", ExternalID: "entry"})
			return err
		}},
		{"CreateMarketplaceCollector", func() error {
			_, err := ledger.CreateMarketplaceCollector(ctx, actor, CreateMarketplaceCollectorInput{Name: "collector", Provider: "scanner", Version: "1", Publisher: "vendor", ManifestHash: sampleDigest("collector")})
			return err
		}},
		{"ListMarketplaceCollectors", func() error { _, err := ledger.ListMarketplaceCollectors(ctx, actor); return err }},
		{"MarketplaceCollectorHealth", func() error { _, err := ledger.MarketplaceCollectorHealth(ctx, actor, "collector"); return err }},
		{"CreatePDFReportPackage", func() error {
			_, err := ledger.CreatePDFReportPackage(ctx, actor, CreatePDFReportPackageInput{ReportType: "release_readiness", ProductID: "prod", ReleaseID: "rel", Title: "Report"})
			return err
		}},
		{"GenerateAnomalyReport", func() error {
			_, err := ledger.GenerateAnomalyReport(ctx, actor, AnomalyReportInput{SubjectType: "release", SubjectID: "rel"})
			return err
		}},
		{"CreateSigningOperation", func() error {
			_, err := ledger.CreateSigningOperation(ctx, actor, CreateSigningOperationInput{ProviderID: "provider", SubjectType: "release", SubjectID: "rel", PayloadHash: sampleDigest("payload"), ExternalSignature: "sig"})
			return err
		}},
		{"VerifyProviderIdentity", func() error {
			_, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: "provider", Subject: "sub"})
			return err
		}},
		{"VerifyCosignSignature", func() error {
			_, err := ledger.VerifyCosignSignature(ctx, actor, VerifyCosignInput{ArtifactSignatureID: "sig"})
			return err
		}},
		{"RevokeSigningKey", func() error { _, err := ledger.RevokeSigningKey(ctx, actor, "key", "reason"); return err }},
		{"CreateSigningProvider", func() error {
			_, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "kms", Type: "aws_kms", KeyRef: "arn:aws:kms:example", Encrypted: true})
			return err
		}},
		{"CreateMerkleBatch", func() error {
			_, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{FromSequence: 1, ToSequence: 1})
			return err
		}},
		{"VerifyMerkleBatch", func() error { _, err := ledger.VerifyMerkleBatch(ctx, actor, "batch"); return err }},
		{"CreateTransparencyCheckpoint", func() error {
			_, err := ledger.CreateTransparencyCheckpoint(ctx, actor, CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "internal", ExternalID: "checkpoint"})
			return err
		}},
		{"CreateObjectRetentionPolicy", func() error {
			_, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "policy", ObjectPrefix: "tenants/ten/", Mode: "governance", RetentionDays: 30})
			return err
		}},
		{"VerifyObjectRetentionPolicy", func() error { _, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, "policy"); return err }},
		{"GenerateBackupManifest", func() error { _, err := ledger.GenerateBackupManifest(ctx, actor); return err }},
		{"VerifyBackupManifest", func() error { _, err := ledger.VerifyBackupManifest(ctx, actor, "backup"); return err }},
		{"ReadinessStatus", func() error { _, err := ledger.ReadinessStatus(ctx); return err }},
		{"Metrics", func() error { _, err := ledger.Metrics(ctx, actor); return err }},
		{"ListAuditLog", func() error { _, err := ledger.ListAuditLog(ctx, actor, AuditLogFilter{}); return err }},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); !errors.Is(err, context.Canceled) {
				t.Fatalf("err=%v, want context.Canceled", err)
			}
		})
	}
}

func TestLedgerOperationsRejectActorsWithoutRequiredScopesBeforeResourceWork(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor := domain.Actor{TenantID: "ten_scope", KeyID: "key_scope"}
	ctx := context.Background()

	checks := []struct {
		name string
		run  func() error
	}{
		{"CreateAPIKey", func() error { _, _, err := ledger.CreateAPIKey(ctx, actor, "key", []string{"*"}, nil); return err }},
		{"ListAPIKeys", func() error { _, err := ledger.ListAPIKeys(ctx, actor); return err }},
		{"CreateProduct", func() error { _, err := ledger.CreateProduct(ctx, actor, "Product", "product"); return err }},
		{"ListProducts", func() error { _, err := ledger.ListProducts(ctx, actor); return err }},
		{"CreateProject", func() error { _, err := ledger.CreateProject(ctx, actor, "prod", "api"); return err }},
		{"CreateRelease", func() error { _, err := ledger.CreateRelease(ctx, actor, "prod", "1.0.0"); return err }},
		{"GetRelease", func() error { _, err := ledger.GetRelease(ctx, actor, "rel"); return err }},
		{"FreezeRelease", func() error { _, err := ledger.FreezeRelease(ctx, actor, "rel"); return err }},
		{"ApproveRelease", func() error { _, err := ledger.ApproveRelease(ctx, actor, "rel"); return err }},
		{"RegisterArtifact", func() error {
			_, err := ledger.RegisterArtifact(ctx, actor, "artifact", "application/octet-stream", sampleDigest("artifact"), 1)
			return err
		}},
		{"CreateEvidence", func() error {
			_, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{Type: "build", Title: "Build"})
			return err
		}},
		{"GetEvidence", func() error { _, err := ledger.GetEvidence(ctx, actor, "ev"); return err }},
		{"ListEvidence", func() error { _, err := ledger.ListEvidence(ctx, actor, "", ""); return err }},
		{"SupersedeEvidence", func() error { _, err := ledger.SupersedeEvidence(ctx, actor, "ev", "ev2", "reason"); return err }},
		{"LinkEvidence", func() error { _, err := ledger.LinkEvidence(ctx, actor, "ev", "release", "rel"); return err }},
		{"UploadSBOM", func() error { _, err := ledger.UploadSBOM(ctx, actor, "rel", "art", []byte(`{}`)); return err }},
		{"UploadVulnerabilityScan", func() error { _, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{}`)); return err }},
		{"UploadOpenAPIContract", func() error {
			_, err := ledger.UploadOpenAPIContract(ctx, actor, "prod", "rel", "v1", []byte(`{}`))
			return err
		}},
		{"EvaluateRelease", func() error { _, err := ledger.EvaluateRelease(ctx, actor, "rel"); return err }},
		{"CreateReleaseBundle", func() error { _, err := ledger.CreateReleaseBundle(ctx, actor, "rel"); return err }},
		{"GetReleaseBundle", func() error { _, err := ledger.GetReleaseBundle(ctx, actor, "bundle"); return err }},
		{"GetSBOM", func() error { _, err := ledger.GetSBOM(ctx, actor, "sbom"); return err }},
		{"ListSBOMComponents", func() error { _, err := ledger.ListSBOMComponents(ctx, actor, ListSBOMComponentsInput{}); return err }},
		{"GetVulnerabilityScan", func() error { _, err := ledger.GetVulnerabilityScan(ctx, actor, "scan"); return err }},
		{"GetOpenAPIContract", func() error { _, err := ledger.GetOpenAPIContract(ctx, actor, "contract"); return err }},
		{"VerifySubject", func() error { _, err := ledger.VerifySubject(ctx, actor, "audit_chain", ""); return err }},
		{"RotateSigningKey", func() error { _, err := ledger.RotateSigningKey(ctx, actor, "reason"); return err }},
		{"ListSigningKeys", func() error { _, err := ledger.ListSigningKeys(ctx, actor); return err }},
		{"MissingEvidenceReport", func() error { _, err := ledger.MissingEvidenceReport(ctx, actor, "rel"); return err }},
		{"SearchEvidence", func() error { _, err := ledger.SearchEvidence(ctx, actor, EvidenceSearchInput{}); return err }},
		{"RecordEvidenceLifecycleEvent", func() error {
			_, err := ledger.RecordEvidenceLifecycleEvent(ctx, actor, "ev", RecordEvidenceLifecycleInput{Action: "amendment", Reason: "reason"})
			return err
		}},
		{"ListEvidenceLifecycleEvents", func() error { _, err := ledger.ListEvidenceLifecycleEvents(ctx, actor, "ev"); return err }},
		{"CreateReleaseCandidate", func() error {
			_, err := ledger.CreateReleaseCandidate(ctx, actor, CreateReleaseCandidateInput{ReleaseID: "rel", Name: "rc"})
			return err
		}},
		{"GetReleaseCandidate", func() error { _, err := ledger.GetReleaseCandidate(ctx, actor, "rc"); return err }},
		{"ListReleaseCandidates", func() error { _, err := ledger.ListReleaseCandidates(ctx, actor, "rel"); return err }},
		{"UpdateReleaseCandidateState", func() error {
			_, err := ledger.UpdateReleaseCandidateState(ctx, actor, "rc", "promoted", "reason")
			return err
		}},
		{"RegisterContainerImage", func() error {
			_, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{ArtifactID: "art", Repository: "repo", Digest: sampleDigest("image")})
			return err
		}},
		{"CreateArtifactSignature", func() error {
			_, err := ledger.CreateArtifactSignature(ctx, actor, CreateArtifactSignatureInput{ArtifactID: "art", Algorithm: "cosign", Signature: "sig"})
			return err
		}},
		{"GetArtifactSignature", func() error { _, err := ledger.GetArtifactSignature(ctx, actor, "sig"); return err }},
		{"CreateSourceRepository", func() error {
			_, err := ledger.CreateSourceRepository(ctx, actor, CreateRepositoryInput{ProjectID: "proj", Provider: "github", FullName: "owner/repo"})
			return err
		}},
		{"ListSourceRepositories", func() error { _, err := ledger.ListSourceRepositories(ctx, actor, "proj"); return err }},
		{"RecordSourceCommit", func() error {
			_, err := ledger.RecordSourceCommit(ctx, actor, RecordCommitInput{RepositoryID: "repo", SHA: "0123456789abcdef0123456789abcdef01234567"})
			return err
		}},
		{"UpsertSourceBranch", func() error {
			_, err := ledger.UpsertSourceBranch(ctx, actor, UpsertBranchInput{RepositoryID: "repo", Name: "main"})
			return err
		}},
		{"RecordPullRequest", func() error {
			_, err := ledger.RecordPullRequest(ctx, actor, RecordPullRequestInput{RepositoryID: "repo", ProviderID: "1", Title: "PR", State: "open"})
			return err
		}},
		{"UploadGitHubSourceSnapshot", func() error { _, err := ledger.UploadGitHubSourceSnapshot(ctx, actor, []byte(`{}`)); return err }},
		{"UploadGitLabSourceSnapshot", func() error { _, err := ledger.UploadGitLabSourceSnapshot(ctx, actor, []byte(`{}`)); return err }},
		{"CreateDeploymentEnvironment", func() error {
			_, err := ledger.CreateDeploymentEnvironment(ctx, actor, CreateEnvironmentInput{ProductID: "prod", Name: "prod", Kind: "production"})
			return err
		}},
		{"ListDeploymentEnvironments", func() error { _, err := ledger.ListDeploymentEnvironments(ctx, actor, "prod"); return err }},
		{"RecordDeployment", func() error {
			_, err := ledger.RecordDeployment(ctx, actor, RecordDeploymentInput{EnvironmentID: "env", ReleaseID: "rel", Status: "started"})
			return err
		}},
		{"GetDeployment", func() error { _, err := ledger.GetDeployment(ctx, actor, "dep"); return err }},
		{"ListDeployments", func() error { _, err := ledger.ListDeployments(ctx, actor, "rel", "env"); return err }},
		{"UploadVEX", func() error { _, err := ledger.UploadVEX(ctx, actor, "rel", "art", []byte(`{}`)); return err }},
		{"GetVEXDocument", func() error { _, err := ledger.GetVEXDocument(ctx, actor, "vex"); return err }},
		{"CreateVulnerabilityDecision", func() error {
			_, err := ledger.CreateVulnerabilityDecision(ctx, actor, "finding", CreateVulnerabilityDecisionInput{Status: "fixed", Justification: "fixed"})
			return err
		}},
		{"CreateException", func() error { _, err := ledger.CreateException(ctx, actor, CreateExceptionInput{}); return err }},
		{"ListExceptions", func() error { _, err := ledger.ListExceptions(ctx, actor, "rel"); return err }},
		{"ApproveException", func() error { _, err := ledger.ApproveException(ctx, actor, "ex"); return err }},
		{"ReleaseReadinessReport", func() error { _, err := ledger.ReleaseReadinessReport(ctx, actor, "rel"); return err }},
		{"CreateControlFramework", func() error {
			_, err := ledger.CreateControlFramework(ctx, actor, CreateControlFrameworkInput{Name: "Framework", Version: "1"})
			return err
		}},
		{"ListControlFrameworks", func() error { _, err := ledger.ListControlFrameworks(ctx, actor); return err }},
		{"CreateSecurityControl", func() error {
			_, err := ledger.CreateSecurityControl(ctx, actor, CreateSecurityControlInput{FrameworkID: "fw", Code: "C", Title: "Control", Objective: "Objective"})
			return err
		}},
		{"GetSecurityControl", func() error { _, err := ledger.GetSecurityControl(ctx, actor, "ctrl"); return err }},
		{"LinkControlEvidence", func() error {
			_, err := ledger.LinkControlEvidence(ctx, actor, "ctrl", LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "sbom", SubjectID: "sbom"})
			return err
		}},
		{"ListControlEvidence", func() error { _, err := ledger.ListControlEvidence(ctx, actor, "ctrl", "prod", "rel"); return err }},
		{"ControlCoverageReport", func() error {
			_, err := ledger.ControlCoverageReport(ctx, actor, ControlCoverageReportInput{FrameworkID: "fw"})
			return err
		}},
		{"CRAReadinessReport", func() error {
			_, err := ledger.CRAReadinessReport(ctx, actor, CRAReadinessReportInput{ProductID: "prod", ReleaseID: "rel"})
			return err
		}},
		{"CreateCollector", func() error {
			_, _, _, err := ledger.CreateCollector(ctx, actor, CreateCollectorInput{Name: "collector", Type: "github_actions", Version: "1"})
			return err
		}},
		{"ListCollectors", func() error { _, err := ledger.ListCollectors(ctx, actor); return err }},
		{"RecordCollectorRelease", func() error {
			_, err := ledger.RecordCollectorRelease(ctx, actor, RecordCollectorReleaseInput{CollectorID: "collector", Version: "1", ArtifactDigest: sampleDigest("collector")})
			return err
		}},
		{"CollectorHealthReport", func() error { _, err := ledger.CollectorHealthReport(ctx, actor, "collector"); return err }},
		{"CreateBuildRun", func() error {
			_, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{ProjectID: "proj", ReleaseID: "rel", Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow()})
			return err
		}},
		{"GetBuildRun", func() error { _, err := ledger.GetBuildRun(ctx, actor, "build"); return err }},
		{"UploadBuildAttestation", func() error { _, err := ledger.UploadBuildAttestation(ctx, actor, "build", []byte(`{}`)); return err }},
		{"CreateWaiver", func() error { _, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{}); return err }},
		{"ApproveWaiver", func() error { _, err := ledger.ApproveWaiver(ctx, actor, "waiver"); return err }},
		{"CreateApprovalRecord", func() error { _, err := ledger.CreateApprovalRecord(ctx, actor, CreateApprovalInput{}); return err }},
		{"CreateRedactionProfile", func() error {
			_, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "profile"})
			return err
		}},
		{"CreateCustomerSecurityPackage", func() error {
			_, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{})
			return err
		}},
		{"AccessCustomerSecurityPackage", func() error { _, err := ledger.AccessCustomerSecurityPackage(ctx, actor, "pkg"); return err }},
		{"ExportCustomerSecurityPackageArchive", func() error { _, err := ledger.ExportCustomerSecurityPackageArchive(ctx, actor, "pkg"); return err }},
		{"SecurityReviewPackageReport", func() error { _, err := ledger.SecurityReviewPackageReport(ctx, actor, "pkg"); return err }},
		{"CRAReadinessHTMLPackage", func() error { _, err := ledger.CRAReadinessHTMLPackage(ctx, actor, "prod", "rel"); return err }},
		{"ListControlFrameworkTemplatePacks", func() error { _, err := ledger.ListControlFrameworkTemplatePacks(ctx, actor); return err }},
		{"InstallControlFrameworkTemplatePack", func() error {
			_, err := ledger.InstallControlFrameworkTemplatePack(ctx, actor, "evydence-cra-readiness")
			return err
		}},
		{"CreateCustomReportTemplate", func() error {
			_, err := ledger.CreateCustomReportTemplate(ctx, actor, CreateReportTemplateInput{Name: "template", Version: "1", ReportType: "summary", Template: "json"})
			return err
		}},
		{"RenderCustomReport", func() error {
			_, err := ledger.RenderCustomReport(ctx, actor, RenderReportInput{TemplateID: "template", SubjectType: "release", SubjectID: "rel"})
			return err
		}},
		{"ExportEvidenceBundle", func() error { _, err := ledger.ExportEvidenceBundle(ctx, actor, "rel", nil); return err }},
		{"ImportEvidenceBundle", func() error { _, err := ledger.ImportEvidenceBundle(ctx, actor, domain.EvidenceBundle{}); return err }},
		{"CreateDSSETrustRoot", func() error {
			_, err := ledger.CreateDSSETrustRoot(ctx, actor, CreateDSSETrustRootInput{Name: "root", KeyID: "root", Algorithm: "Ed25519", PublicKey: "pub"})
			return err
		}},
		{"VerifyDSSEAttestationSignature", func() error { _, err := ledger.VerifyDSSEAttestationSignature(ctx, actor, "att"); return err }},
		{"CreateOrganization", func() error {
			_, err := ledger.CreateOrganization(ctx, actor, CreateOrganizationInput{Name: "Org", Slug: "org"})
			return err
		}},
		{"CreateUser", func() error {
			_, err := ledger.CreateUser(ctx, actor, CreateUserInput{OrganizationID: "org", Email: "user@example.test"})
			return err
		}},
		{"DeactivateUser", func() error { _, err := ledger.DeactivateUser(ctx, actor, "user"); return err }},
		{"CreateRoleBinding", func() error {
			_, err := ledger.CreateRoleBinding(ctx, actor, CreateRoleBindingInput{SubjectType: "user", SubjectID: "user", Role: "tenant_admin", ResourceType: "tenant"})
			return err
		}},
		{"ListRoleBindings", func() error { _, err := ledger.ListRoleBindings(ctx, actor); return err }},
		{"CreateSSOProvider", func() error {
			_, err := ledger.CreateSSOProvider(ctx, actor, CreateSSOProviderInput{Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client"})
			return err
		}},
		{"LinkSSOIdentity", func() error {
			_, err := ledger.LinkSSOIdentity(ctx, actor, LinkSSOIdentityInput{UserID: "user", ProviderID: "provider", Subject: "sub", Email: "user@example.test"})
			return err
		}},
		{"CreateSSOSession", func() error {
			_, _, err := ledger.CreateSSOSession(ctx, actor, CreateSSOSessionInput{UserID: "user", ProviderID: "provider", ExpiresAt: fixedNow().AddDate(0, 0, 1)})
			return err
		}},
		{"RevokeSSOSession", func() error { _, err := ledger.RevokeSSOSession(ctx, actor, "session"); return err }},
		{"InstanceAdminSnapshot", func() error { _, err := ledger.InstanceAdminSnapshot(ctx, actor); return err }},
		{"CreateLegalHold", func() error {
			_, err := ledger.CreateLegalHold(ctx, actor, CreateLegalHoldInput{ScopeType: "release", ScopeID: "rel", Reason: "review", Owner: "legal"})
			return err
		}},
		{"CreateRetentionOverride", func() error {
			_, err := ledger.CreateRetentionOverride(ctx, actor, CreateRetentionOverrideInput{ScopeType: "release", ScopeID: "rel", RetentionUntil: fixedNow().AddDate(1, 0, 0), Reason: "review", Owner: "legal"})
			return err
		}},
		{"RetentionReport", func() error { _, err := ledger.RetentionReport(ctx, actor, "release", "rel"); return err }},
		{"CreateCustomerPortalAccess", func() error {
			_, _, err := ledger.CreateCustomerPortalAccess(ctx, actor, CreateCustomerPortalAccessInput{PackageID: "pkg", CustomerName: "ACME", ExpiresAt: fixedNow().AddDate(0, 0, 1)})
			return err
		}},
		{"CreateQuestionnaireTemplate", func() error {
			_, err := ledger.CreateQuestionnaireTemplate(ctx, actor, CreateQuestionnaireTemplateInput{Name: "template", Version: "1"})
			return err
		}},
		{"CreateQuestionnairePackage", func() error {
			_, err := ledger.CreateQuestionnairePackage(ctx, actor, CreateQuestionnairePackageInput{TemplateID: "template", PackageID: "pkg", ProductID: "prod", ReleaseID: "rel"})
			return err
		}},
		{"CreateCommercialCollectorDefinition", func() error {
			_, err := ledger.CreateCommercialCollectorDefinition(ctx, actor, CreateCommercialCollectorInput{Name: "collector", Provider: "jira", Version: "1", ManifestHash: sampleDigest("collector")})
			return err
		}},
		{"ListCommercialCollectorDefinitions", func() error { _, err := ledger.ListCommercialCollectorDefinitions(ctx, actor); return err }},
		{"CreateEvidenceSummary", func() error {
			_, err := ledger.CreateEvidenceSummary(ctx, actor, CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: "rel"})
			return err
		}},
		{"CreateQuestionnaireDraft", func() error {
			_, err := ledger.CreateQuestionnaireDraft(ctx, actor, CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "prod", ReleaseID: "rel"})
			return err
		}},
		{"CreateGraphSnapshot", func() error {
			_, err := ledger.CreateGraphSnapshot(ctx, actor, CreateGraphSnapshotInput{ProductID: "prod", ReleaseID: "rel"})
			return err
		}},
		{"CreateSaaSEditionProfile", func() error {
			_, err := ledger.CreateSaaSEditionProfile(ctx, actor, CreateSaaSEditionProfileInput{Name: "profile", Region: "eu", AdminTenantID: "ten", IsolationModel: "self-hosted"})
			return err
		}},
		{"CreatePublicTransparencyLog", func() error {
			_, err := ledger.CreatePublicTransparencyLog(ctx, actor, CreatePublicTransparencyLogInput{Name: "log", Endpoint: "https://log.example.test", PublicKey: "pub"})
			return err
		}},
		{"PublishPublicTransparencyLogEntry", func() error {
			_, err := ledger.PublishPublicTransparencyLogEntry(ctx, actor, PublishPublicTransparencyLogEntryInput{LogID: "log", CheckpointID: "checkpoint", ExternalID: "entry"})
			return err
		}},
		{"CreateMarketplaceCollector", func() error {
			_, err := ledger.CreateMarketplaceCollector(ctx, actor, CreateMarketplaceCollectorInput{Name: "collector", Provider: "scanner", Version: "1", Publisher: "vendor", ManifestHash: sampleDigest("collector")})
			return err
		}},
		{"ListMarketplaceCollectors", func() error { _, err := ledger.ListMarketplaceCollectors(ctx, actor); return err }},
		{"MarketplaceCollectorHealth", func() error { _, err := ledger.MarketplaceCollectorHealth(ctx, actor, "collector"); return err }},
		{"CreatePDFReportPackage", func() error {
			_, err := ledger.CreatePDFReportPackage(ctx, actor, CreatePDFReportPackageInput{ReportType: "release_readiness", ProductID: "prod", ReleaseID: "rel", Title: "Report"})
			return err
		}},
		{"GenerateAnomalyReport", func() error {
			_, err := ledger.GenerateAnomalyReport(ctx, actor, AnomalyReportInput{SubjectType: "release", SubjectID: "rel"})
			return err
		}},
		{"CreateSigningOperation", func() error {
			_, err := ledger.CreateSigningOperation(ctx, actor, CreateSigningOperationInput{ProviderID: "provider", SubjectType: "release", SubjectID: "rel", PayloadHash: sampleDigest("payload"), ExternalSignature: "sig"})
			return err
		}},
		{"VerifyProviderIdentity", func() error {
			_, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: "provider", Subject: "sub"})
			return err
		}},
		{"VerifyCosignSignature", func() error {
			_, err := ledger.VerifyCosignSignature(ctx, actor, VerifyCosignInput{ArtifactSignatureID: "sig"})
			return err
		}},
		{"RevokeSigningKey", func() error { _, err := ledger.RevokeSigningKey(ctx, actor, "key", "reason"); return err }},
		{"CreateSigningProvider", func() error {
			_, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "kms", Type: "aws_kms", KeyRef: "arn:aws:kms:example", Encrypted: true})
			return err
		}},
		{"CreateMerkleBatch", func() error {
			_, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{FromSequence: 1, ToSequence: 1})
			return err
		}},
		{"VerifyMerkleBatch", func() error { _, err := ledger.VerifyMerkleBatch(ctx, actor, "batch"); return err }},
		{"CreateTransparencyCheckpoint", func() error {
			_, err := ledger.CreateTransparencyCheckpoint(ctx, actor, CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "internal", ExternalID: "checkpoint"})
			return err
		}},
		{"CreateObjectRetentionPolicy", func() error {
			_, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "policy", ObjectPrefix: "tenants/ten/", Mode: "governance", RetentionDays: 30})
			return err
		}},
		{"VerifyObjectRetentionPolicy", func() error { _, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, "policy"); return err }},
		{"GenerateBackupManifest", func() error { _, err := ledger.GenerateBackupManifest(ctx, actor); return err }},
		{"VerifyBackupManifest", func() error { _, err := ledger.VerifyBackupManifest(ctx, actor, "backup"); return err }},
		{"Metrics", func() error { _, err := ledger.Metrics(ctx, actor); return err }},
		{"ListAuditLog", func() error { _, err := ledger.ListAuditLog(ctx, actor, AuditLogFilter{}); return err }},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); !errors.Is(err, ErrForbidden) {
				t.Fatalf("err=%v, want ErrForbidden", err)
			}
		})
	}
}
