package wiring

import (
	"errors"
	"fmt"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// BuildAPIReadServices composes the API's durable authentication, focused
// queries, and operator replay command from one validated runtime. Local
// memory deliberately keeps the explicit Ledger fallback.
func BuildAPIReadServices(runtime *Runtime, pepper string, readinessChecks []app.ReadinessCheck) (httpapi.ServerOptions, error) {
	if runtime == nil {
		return httpapi.ServerOptions{}, errors.New("API runtime is required")
	}
	if runtime.Process != API {
		return httpapi.ServerOptions{}, errors.New("API read services require an API runtime")
	}
	switch runtime.Profile {
	case LocalMemory:
		if runtime.Production || runtime.Postgres != nil {
			return httpapi.ServerOptions{}, errors.New("local-memory API runtime is inconsistent")
		}
		return httpapi.ServerOptions{}, nil
	case PostgreSQL:
		if runtime.Postgres == nil {
			return httpapi.ServerOptions{}, errors.New("PostgreSQL API runtime is incomplete")
		}
	default:
		return httpapi.ServerOptions{}, errors.New("unsupported API runtime profile")
	}
	store := runtime.Postgres
	var options httpapi.ServerOptions
	var err error
	normalizedChecks := operationsquery.NormalizeReadinessChecks(readinessChecks)
	configuredChecks := make(map[string]bool, len(normalizedChecks))
	for _, check := range normalizedChecks {
		configuredChecks[check.Name] = true
	}
	for _, required := range []string{"postgres", "migrations"} {
		if !configuredChecks[required] {
			return httpapi.ServerOptions{}, errors.New("PostgreSQL API readiness checks are incomplete")
		}
	}
	if runtime.Production && (!configuredChecks["writer_lease"] || !configuredChecks["signing_config"]) {
		return httpapi.ServerOptions{}, errors.New("production API readiness checks are incomplete")
	}
	options.ReadinessQuery = operationsquery.NewReadiness(normalizedChecks)
	options.MetricsQuery, err = BuildMetricsQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create metrics query: %w", err)
	}
	options.RetentionQuery, err = BuildRetentionQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create retention query: %w", err)
	}
	options.IncidentReportQuery, err = BuildIncidentReportQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create incident report query: %w", err)
	}
	options.SecurityUpdateEvidenceQuery, err = BuildSecurityUpdateEvidenceQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create security update evidence query: %w", err)
	}
	options.CRAVulnerabilityQuery, err = BuildCRAVulnerabilityHandlingQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create CRA vulnerability handling query: %w", err)
	}
	options.MissingEvidenceQuery, err = BuildMissingEvidenceQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create missing evidence query: %w", err)
	}
	options.ReleaseReadinessReportQuery, err = BuildReleaseReadinessReportQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release readiness report query: %w", err)
	}
	options.CustomerPackageAccessCommands, err = BuildCustomerPackageAccessCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create customer package access commands: %w", err)
	}
	options.ReleaseSecuritySummaryQuery, err = BuildReleaseSecuritySummaryQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release security summary query: %w", err)
	}
	options.ControlCoverageQuery, err = BuildControlCoverageQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create control coverage query: %w", err)
	}
	options.HTMLReportCommands, err = BuildHTMLReportCommands(options.ControlCoverageQuery, store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create HTML report commands: %w", err)
	}
	options.ReportTemplateCommands, err = BuildReportTemplateCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create report template commands: %w", err)
	}
	options.BundleImportCommand, err = BuildBundleImportCommand(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create bundle import command: %w", err)
	}
	options.ReleaseBundleCommands, err = BuildReleaseBundleCommands(store, store, store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release bundle commands: %w", err)
	}
	options.EvidenceBundleCommands, err = BuildEvidenceBundleCommands(store, store, store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create evidence bundle commands: %w", err)
	}
	options.SigningKeyCommands, err = BuildSigningKeyCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create signing-key commands: %w", err)
	}
	options.ReleaseBundleVerification, err = BuildReleaseBundleVerificationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release bundle verification: %w", err)
	}
	options.EvidenceVerification, err = BuildEvidenceVerificationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create evidence verification: %w", err)
	}
	options.DSSEVerification, err = BuildDSSEVerificationCommands(store, runtime.Objects)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create DSSE verification: %w", err)
	}
	options.CosignVerification, err = BuildCosignVerificationCommands(store, runtime.Objects, runtime.Cosign)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create Cosign verification: %w", err)
	}
	options.ArtifactSignatureVerification, err = BuildArtifactSignatureVerificationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create artifact signature metadata verification: %w", err)
	}
	options.MerkleVerification, err = BuildMerkleVerificationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create Merkle verification: %w", err)
	}
	options.AuditChainVerification, err = BuildAuditChainVerificationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create audit chain verification: %w", err)
	}
	options.MerkleCheckpointVerification, err = BuildMerkleCheckpointVerificationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create Merkle audit chain checkpoint verification: %w", err)
	}
	options.ReleaseManifestCheckpoint, err = BuildReleaseManifestCheckpointCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release manifest checkpoint verification: %w", err)
	}
	options.BackupVerification, err = BuildBackupVerificationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create backup verification: %w", err)
	}
	options.TransparencyCheckpointCommands, err = BuildTransparencyCheckpointCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create transparency checkpoint commands: %w", err)
	}
	options.MerkleCreationCommands, err = BuildMerkleCreationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create Merkle creation commands: %w", err)
	}
	options.BackupGenerationCommands, err = BuildBackupGenerationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create backup generation commands: %w", err)
	}
	options.ArtifactSignatureCommands, err = BuildArtifactSignatureCommands(store, store, runtime.Objects)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create artifact signature commands: %w", err)
	}
	options.BuildCommands, err = BuildBuildCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create build commands: %w", err)
	}
	options.ContainerImageCommands, err = BuildContainerImageCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create container image commands: %w", err)
	}
	options.ArtifactCommands, err = BuildArtifactCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create artifact commands: %w", err)
	}
	options.ProjectCommands, err = BuildProjectCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create project commands: %w", err)
	}
	options.ReleaseCreationCommands, err = BuildReleaseCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release creation commands: %w", err)
	}
	options.BuildAttestationCommands, err = BuildBuildAttestationCommands(store, runtime.Objects, runtime.WorkerOwnedParsers)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create build attestation commands: %w", err)
	}
	options.EvidenceCreationCommands, err = BuildEvidenceCreationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create evidence creation commands: %w", err)
	}
	options.DeploymentEnvironmentCommands, err = BuildDeploymentEnvironmentCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create environment commands: %w", err)
	}
	options.DeploymentCommands, err = BuildDeploymentCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create deployment commands: %w", err)
	}
	options.SourceRepositoryCommands, err = BuildSourceRepositoryCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create source repository commands: %w", err)
	}
	options.SourceCommitCommands, err = BuildSourceCommitCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create source commit commands: %w", err)
	}
	options.SourceBranchCommands, err = BuildSourceBranchCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create source branch commands: %w", err)
	}
	options.PullRequestCommands, err = BuildPullRequestCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create pull request commands: %w", err)
	}
	options.SourceSnapshotCommands, err = BuildSourceSnapshotCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create source snapshot commands: %w", err)
	}
	options.SubjectVerification, err = verificationapp.NewSubjectVerificationCommands(verificationapp.SubjectVerificationConfig{
		Authorizer: verificationquery.NewEvidenceVerificationAuthorizer(),
		AuditChain: options.AuditChainVerification, Evidence: options.EvidenceVerification,
		ReleaseBundle: options.ReleaseBundleVerification, DSSE: options.DSSEVerification,
		ArtifactSignature: options.ArtifactSignatureVerification, Merkle: options.MerkleVerification,
		MerkleCheckpoint:          options.MerkleCheckpointVerification,
		ReleaseManifestCheckpoint: options.ReleaseManifestCheckpoint, Backup: options.BackupVerification,
	})
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create generic subject verification: %w", err)
	}
	options.SigningCustodyQuery, err = BuildSigningCustodyQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create signing custody query: %w", err)
	}
	retentionVerifier, _ := runtime.Objects.(app.ObjectRetentionVerifier)
	options.RetentionCommands, err = BuildRetentionCommands(store, store, retentionVerifier)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create retention commands: %w", err)
	}
	options.TrustConfigurationCommands, err = BuildTrustConfigurationCommands(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create trust configuration commands: %w", err)
	}
	options.Authenticator, err = BuildAuthenticator(store, store, pepper, runtime.Production)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create authenticator: %w", err)
	}
	options.InstanceAdminQuery, err = BuildInstanceAdminQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create instance admin query: %w", err)
	}
	options.OutboxDiagnosticsQuery, err = BuildOutboxDiagnosticsQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create outbox diagnostics query: %w", err)
	}
	options.OutboxReplayCommand, err = BuildOutboxReplayCommand(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create outbox replay command: %w", err)
	}
	options.ProductQuery, err = BuildProductQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create product query: %w", err)
	}
	options.CatalogPointQuery, err = BuildCatalogPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create catalog point query: %w", err)
	}
	options.EvidenceFlowQuery, err = BuildEvidenceFlowQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release evidence flow query: %w", err)
	}
	options.BuildPointQuery, err = BuildBuildPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create build point query: %w", err)
	}
	options.ArtifactPointQuery, err = BuildArtifactPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create artifact point query: %w", err)
	}
	options.ReleaseCandidateQuery, err = BuildReleaseCandidateQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release candidate query: %w", err)
	}
	options.DeploymentPointQuery, err = BuildDeploymentPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create deployment point query: %w", err)
	}
	options.DeploymentListQuery, err = BuildDeploymentListQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create deployment list query: %w", err)
	}
	options.EvidencePointQuery, err = BuildEvidencePointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create evidence point query: %w", err)
	}
	options.LifecycleEventsQuery, err = BuildLifecycleEventsQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create lifecycle events query: %w", err)
	}
	options.OpenAPIContractPointQuery, err = BuildOpenAPIContractPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create OpenAPI contract point query: %w", err)
	}
	options.SBOMPointQuery, err = BuildSBOMPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create SBOM point query: %w", err)
	}
	options.VulnerabilityScanPointQuery, err = BuildVulnerabilityScanPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create vulnerability scan point query: %w", err)
	}
	options.VEXPointQuery, err = BuildVEXPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create VEX point query: %w", err)
	}
	options.SBOMComponentsQuery, err = BuildSBOMComponentsQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create SBOM components query: %w", err)
	}
	options.SourceRepositoryQuery, err = BuildSourceRepositoryQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create source repository query: %w", err)
	}
	options.CollectorQuery, err = BuildCollectorQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create collector query: %w", err)
	}
	options.CollectorHealthQuery, err = BuildCollectorHealthQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create collector health query: %w", err)
	}
	options.CommercialCollectorQuery, err = BuildCommercialCollectorQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create commercial collector query: %w", err)
	}
	options.MarketplaceCollectorQuery, err = BuildMarketplaceCollectorQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create marketplace collector query: %w", err)
	}
	options.VulnerabilityPostureQuery, err = BuildVulnerabilityPostureQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create vulnerability posture query: %w", err)
	}
	controls, err := BuildControlsQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create controls query: %w", err)
	}
	options.ControlsQuery = controls
	options.ControlTemplateQuery = controls
	options.ExceptionsQuery, err = BuildExceptionsQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create exceptions query: %w", err)
	}
	options.VulnerabilityDecisionQuery, err = BuildVulnerabilityDecisionQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create vulnerability decision query: %w", err)
	}
	options.VulnerabilityDecisionSummaryQuery, err = BuildVulnerabilityDecisionSummaryQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create vulnerability decision summary query: %w", err)
	}
	options.ControlEvidenceQuery, err = BuildControlEvidenceQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create control evidence query: %w", err)
	}
	options.ArtifactSignatureQuery, err = BuildArtifactSignatureQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create artifact signature query: %w", err)
	}
	options.ReleaseBundleQuery, err = BuildReleaseBundleQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release bundle query: %w", err)
	}
	options.AnswerLibraryQuery, err = BuildAnswerLibraryQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create answer library query: %w", err)
	}
	options.PortalAccessQuery, err = BuildPortalAccessQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create portal access query: %w", err)
	}
	options.SigningKeyQuery, err = BuildSigningKeyQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create signing key query: %w", err)
	}
	options.AuditLogQuery, err = BuildAuditLogQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create audit log query: %w", err)
	}
	options.APIKeyQuery, err = BuildAPIKeyQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create API-key query: %w", err)
	}
	options.RoleBindingQuery, err = BuildRoleBindingQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create role-binding query: %w", err)
	}
	return options, nil
}
