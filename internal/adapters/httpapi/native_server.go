package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
)

// NewNativeServerWithOptionsContext composes the complete durable API surface.
// It never constructs, accepts or binds a Ledger or local-memory replay adapter.
// Missing ports fail at startup rather than enabling a compatibility fallback.
func NewNativeServerWithOptionsContext(ctx context.Context, options ServerOptions) (*Server, error) {
	if ctx == nil {
		return nil, errors.New("server context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateNativeServerOptions(options); err != nil {
		return nil, err
	}
	return newServerWithOptionsContext(ctx, nil, options, false)
}
func validateNativeServerOptions(options ServerOptions) error {
	dependencies := []struct {
		name string
		port any
	}{
		{"Authenticator", options.Authenticator},
		{"APIKeyCommands", options.APIKeyCommands},
		{"MembershipCommands", options.MembershipCommands},
		{"RoleBindingCommands", options.RoleBindingCommands},
		{"SSOProviderCommands", options.SSOProviderCommands},
		{"SSOIdentityLinkCommands", options.SSOIdentityLinkCommands},
		{"SSOSessionCommands", options.SSOSessionCommands},
		{"SSOSessionRevocationCommands", options.SSOSessionRevocationCommands},
		{"SSOExchangeCommands", options.SSOExchangeCommands},
		{"ProviderVerificationCommands", options.ProviderVerificationCommands},
		{"EvidenceSummaryCommands", options.EvidenceSummaryCommands},
		{"GraphSnapshotCommands", options.GraphSnapshotCommands},
		{"PDFReportCommands", options.PDFReportCommands},
		{"AnomalyReportCommands", options.AnomalyReportCommands},
		{"SigningOperationCommands", options.SigningOperationCommands},
		{"SaaSProfileCommands", options.SaaSProfileCommands},
		{"MarketplaceCollectorCommands", options.MarketplaceCollectorCommands},
		{"PublicTransparencyMetadataCommands", options.PublicTransparencyMetadataCommands},
		{"PublicTransparencyProofCommands", options.PublicTransparencyProofCommands},
		{"PublicTransparencyFetchCommands", options.PublicTransparencyFetchCommands},
		{"QuestionnaireDraftCommands", options.QuestionnaireDraftCommands},
		{"QuestionnairePackageCommands", options.QuestionnairePackageCommands},
		{"PortalAccessCommands", options.PortalAccessCommands},
		{"PortalTokenCommands", options.PortalTokenCommands},
		{"QuestionnaireTemplateCommands", options.QuestionnaireTemplateCommands},
		{"RedactionProfileCommands", options.RedactionProfileCommands},
		{"AnswerLibraryCommands", options.AnswerLibraryCommands},
		{"ReadinessQuery", options.ReadinessQuery},
		{"MetricsQuery", options.MetricsQuery},
		{"RetentionQuery", options.RetentionQuery},
		{"IncidentReportQuery", options.IncidentReportQuery},
		{"SecurityUpdateEvidenceQuery", options.SecurityUpdateEvidenceQuery},
		{"CRAVulnerabilityQuery", options.CRAVulnerabilityQuery},
		{"MissingEvidenceQuery", options.MissingEvidenceQuery},
		{"ReleaseReadinessReportQuery", options.ReleaseReadinessReportQuery},
		{"CustomerPackageAccessCommands", options.CustomerPackageAccessCommands},
		{"CustomerPackageCreationCommands", options.CustomerPackageCreationCommands},
		{"HTMLReportCommands", options.HTMLReportCommands},
		{"ReportTemplateCommands", options.ReportTemplateCommands},
		{"BundleImportCommand", options.BundleImportCommand},
		{"ReleaseBundleCommands", options.ReleaseBundleCommands},
		{"EvidenceBundleCommands", options.EvidenceBundleCommands},
		{"SigningKeyCommands", options.SigningKeyCommands},
		{"ReleaseBundleVerification", options.ReleaseBundleVerification},
		{"EvidenceVerification", options.EvidenceVerification},
		{"DSSEVerification", options.DSSEVerification},
		{"CosignVerification", options.CosignVerification},
		{"ArtifactSignatureVerification", options.ArtifactSignatureVerification},
		{"MerkleVerification", options.MerkleVerification},
		{"AuditChainVerification", options.AuditChainVerification},
		{"MerkleCheckpointVerification", options.MerkleCheckpointVerification},
		{"ReleaseManifestCheckpoint", options.ReleaseManifestCheckpoint},
		{"BackupVerification", options.BackupVerification},
		{"BackupGenerationCommands", options.BackupGenerationCommands},
		{"ArtifactSignatureCommands", options.ArtifactSignatureCommands},
		{"BuildAttestationCommands", options.BuildAttestationCommands},
		{"BuildCommands", options.BuildCommands},
		{"ContainerImageCommands", options.ContainerImageCommands},
		{"ArtifactCommands", options.ArtifactCommands},
		{"ProductCommands", options.ProductCommands},
		{"ProjectCommands", options.ProjectCommands},
		{"ReleaseCreationCommands", options.ReleaseCreationCommands},
		{"ReleaseStateCommands", options.ReleaseStateCommands},
		{"CandidateStateCommands", options.CandidateStateCommands},
		{"CandidateCommands", options.CandidateCommands},
		{"ControlCommands", options.ControlCommands},
		{"ControlTemplateCommands", options.ControlTemplateCommands},
		{"ControlEvidenceCommands", options.ControlEvidenceCommands},
		{"VulnerabilityDecisionCommands", options.VulnerabilityDecisionCommands},
		{"ApprovalCommands", options.ApprovalCommands},
		{"WaiverCommands", options.WaiverCommands},
		{"ExceptionCommands", options.ExceptionCommands},
		{"VulnerabilityWorkflowCommands", options.VulnerabilityWorkflowCommands},
		{"CustomPolicyCommands", options.CustomPolicyCommands},
		{"PolicyEvaluationCommands", options.PolicyEvaluationCommands},
		{"SBOMDiffCommands", options.SBOMDiffCommands},
		{"ContractDiffCommands", options.ContractDiffCommands},
		{"DurableCommandExecutor", options.DurableCommandExecutor},
		{"EvidenceCreationCommands", options.EvidenceCreationCommands},
		{"EvidenceRelationshipCommands", options.EvidenceRelationshipCommands},
		{"OpenAPIIngestionCommands", options.OpenAPIIngestionCommands},
		{"SBOMIngestionCommands", options.SBOMIngestionCommands},
		{"ScanIngestionCommands", options.ScanIngestionCommands},
		{"VEXIngestionCommands", options.VEXIngestionCommands},
		{"VEXPreviewQuery", options.VEXPreviewQuery},
		{"SecurityDocumentCommands", options.SecurityDocumentCommands},
		{"IncidentCommands", options.IncidentCommands},
		{"IncidentWebhookCommands", options.IncidentWebhookCommands},
		{"CollectorCommands", options.CollectorCommands},
		{"DeploymentEnvironmentCommands", options.DeploymentEnvironmentCommands},
		{"DeploymentCommands", options.DeploymentCommands},
		{"SourceRepositoryCommands", options.SourceRepositoryCommands},
		{"SourceCommitCommands", options.SourceCommitCommands},
		{"SourceBranchCommands", options.SourceBranchCommands},
		{"PullRequestCommands", options.PullRequestCommands},
		{"SourceSnapshotCommands", options.SourceSnapshotCommands},
		{"SubjectVerification", options.SubjectVerification},
		{"TransparencyCheckpointCommands", options.TransparencyCheckpointCommands},
		{"MerkleCreationCommands", options.MerkleCreationCommands},
		{"SigningCustodyQuery", options.SigningCustodyQuery},
		{"RetentionCommands", options.RetentionCommands},
		{"RetentionMarkerCommands", options.RetentionMarkerCommands},
		{"TrustConfigurationCommands", options.TrustConfigurationCommands},
		{"ReleaseSecuritySummaryQuery", options.ReleaseSecuritySummaryQuery},
		{"ControlCoverageQuery", options.ControlCoverageQuery},
		{"InstanceAdminQuery", options.InstanceAdminQuery},
		{"OutboxDiagnosticsQuery", options.OutboxDiagnosticsQuery},
		{"OutboxReplayCommand", options.OutboxReplayCommand},
		{"ProductQuery", options.ProductQuery},
		{"CatalogPointQuery", options.CatalogPointQuery},
		{"EvidenceFlowQuery", options.EvidenceFlowQuery},
		{"BuildPointQuery", options.BuildPointQuery},
		{"ArtifactPointQuery", options.ArtifactPointQuery},
		{"ReleaseCandidateQuery", options.ReleaseCandidateQuery},
		{"DeploymentPointQuery", options.DeploymentPointQuery},
		{"DeploymentListQuery", options.DeploymentListQuery},
		{"EvidencePointQuery", options.EvidencePointQuery},
		{"EvidencePageQuery", options.EvidencePageQuery},
		{"LifecycleEventsQuery", options.LifecycleEventsQuery},
		{"OpenAPIContractPointQuery", options.OpenAPIContractPointQuery},
		{"SBOMPointQuery", options.SBOMPointQuery},
		{"VulnerabilityScanPointQuery", options.VulnerabilityScanPointQuery},
		{"VEXPointQuery", options.VEXPointQuery},
		{"SBOMComponentsQuery", options.SBOMComponentsQuery},
		{"SourceRepositoryQuery", options.SourceRepositoryQuery},
		{"CollectorQuery", options.CollectorQuery},
		{"CollectorHealthQuery", options.CollectorHealthQuery},
		{"CommercialCollectorQuery", options.CommercialCollectorQuery},
		{"MarketplaceCollectorQuery", options.MarketplaceCollectorQuery},
		{"VulnerabilityPostureQuery", options.VulnerabilityPostureQuery},
		{"ControlsQuery", options.ControlsQuery},
		{"ControlTemplateQuery", options.ControlTemplateQuery},
		{"ExceptionsQuery", options.ExceptionsQuery},
		{"VulnerabilityDecisionQuery", options.VulnerabilityDecisionQuery},
		{"VulnerabilityDecisionSummaryQuery", options.VulnerabilityDecisionSummaryQuery},
		{"ControlEvidenceQuery", options.ControlEvidenceQuery},
		{"ArtifactSignatureQuery", options.ArtifactSignatureQuery},
		{"SigningKeyQuery", options.SigningKeyQuery},
		{"ReleaseBundleQuery", options.ReleaseBundleQuery},
		{"AnswerLibraryQuery", options.AnswerLibraryQuery},
		{"PortalAccessQuery", options.PortalAccessQuery},
		{"AuditLogQuery", options.AuditLogQuery},
		{"APIKeyQuery", options.APIKeyQuery},
		{"RoleBindingQuery", options.RoleBindingQuery},
	}
	for _, dependency := range dependencies {
		if nativePortMissing(dependency.port) {
			return fmt.Errorf("native server requires %s", dependency.name)
		}
	}
	if len(options.PaginationSecret) < 16 {
		return errors.New("native server requires PaginationSecret of at least 16 bytes")
	}
	if _, ok := options.DurableCommandExecutor.(DurableStreamedCommandExecutor); !ok {
		return errors.New("native server requires DurableCommandExecutor streamed capability")
	}
	if _, ok := options.DurableCommandExecutor.(DurableReplayCommandExecutor); !ok {
		return errors.New("native server requires DurableCommandExecutor historical replay capability")
	}
	return nil
}
func nativePortMissing(port any) bool {
	if port == nil {
		return true
	}
	value := reflect.ValueOf(port)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
