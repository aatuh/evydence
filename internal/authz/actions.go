// Package authz owns transport-neutral authorization policy. Actions identify
// use cases; scopes are credential capabilities, not caller-selected policy.
package authz

// Action identifies a registered application operation. Unknown actions deny.
type Action string

const (
	ActionAPIKeysRead                      Action = "api_keys.read" // #nosec G101 -- Public policy action identifier, not credential material.
	ActionAPIKeysManage                    Action = "api_keys.manage"
	ActionMembershipsManage                Action = "memberships.manage"
	ActionRoleBindingsRead                 Action = "role_bindings.read"
	ActionControlsRead                     Action = "controls.read"
	ActionControlsManage                   Action = "controls.manage"
	ActionVulnerabilityPostureRead         Action = "vulnerability_posture.read"
	ActionControlCoverageRead              Action = "control_coverage.read"
	ActionCollectorsRead                   Action = "collectors.read"
	ActionCommercialCollectorsRead         Action = "commercial_collectors.read"
	ActionCollectorHealthRead              Action = "collector_health.read"
	ActionCollectorsManage                 Action = "collectors.manage"
	ActionMarketplaceCollectorsRead        Action = "marketplace_collectors.read"
	ActionMarketplaceCollectorsManage      Action = "marketplace_collectors.manage"
	ActionSigningCustodyRead               Action = "signing_custody.read"
	ActionSigningKeysManage                Action = "signing_keys.manage"
	ActionTransparencyMetadataPublish      Action = "transparency_metadata.publish"
	ActionSigningKeysRead                  Action = "signing_keys.read"
	ActionRetentionPoliciesRead            Action = "retention_policies.read"
	ActionRetentionPoliciesManage          Action = "retention_policies.manage"
	ActionRetentionReportRead              Action = "retention_report.read"
	ActionRetentionMarkersManage           Action = "retention_markers.manage"
	ActionAuditLogRead                     Action = "audit_log.read"
	ActionTenantMetricsRead                Action = "tenant_metrics.read"
	ActionReportTemplatesManage            Action = "report_templates.manage"
	ActionBundleImport                     Action = "bundle.import"
	ActionQuestionnaireTemplatesManage     Action = "questionnaire_templates.manage"
	ActionRedactionProfilesManage          Action = "redaction_profiles.manage"
	ActionInstanceSnapshotRead             Action = "instance_snapshot.read"
	ActionInstanceReadinessRead            Action = "instance_readiness.read"
	ActionInstanceMetricsRead              Action = "instance_metrics.read"
	ActionOutboxDiagnosticsRead            Action = "outbox_diagnostics.read"
	ActionOutboxReplay                     Action = "outbox.replay"
	ActionSaaSProfilesManage               Action = "saas_profiles.manage"
	ActionTenantSubjectVerify              Action = "tenant_subject.verify"
	ActionBackupGenerate                   Action = "backup.generate"
	ActionProductsRead                     Action = "products.read"
	ActionProductsCreate                   Action = "products.create"
	ActionProjectsRead                     Action = "projects.read"
	ActionProjectsCreate                   Action = "projects.create"
	ActionReleasesRead                     Action = "releases.read"
	ActionReleasesManage                   Action = "releases.manage"
	ActionBuildsRead                       Action = "builds.read"
	ActionBuildsCreate                     Action = "builds.create"
	ActionBuildAttestationsCreate          Action = "build_attestations.create"
	ActionReleaseCandidatesCreate          Action = "release_candidates.create"
	ActionReleaseCandidatesRead            Action = "release_candidates.read"
	ActionEnvironmentsRead                 Action = "environments.read"
	ActionEnvironmentsCreate               Action = "environments.create"
	ActionDeploymentsRead                  Action = "deployments.read"
	ActionDeploymentsRecord                Action = "deployments.record"
	ActionIncidentsManage                  Action = "incidents.manage"
	ActionVulnerabilityDecisionsRecord     Action = "vulnerability_decisions.record"
	ActionApprovalsRecord                  Action = "approvals.record"
	ActionWaiversManage                    Action = "waivers.manage"
	ActionExceptionsManage                 Action = "exceptions.manage"
	ActionVulnerabilityWorkflowsRecord     Action = "vulnerability_workflows.record"
	ActionPolicyEvaluationsCreate          Action = "policy_evaluations.create"
	ActionCustomPoliciesCreate             Action = "custom_policies.create"
	ActionCustomPoliciesEvaluate           Action = "custom_policies.evaluate"
	ActionVulnerabilityDecisionsRead       Action = "vulnerability_decisions.read"
	ActionExceptionsRead                   Action = "exceptions.read"
	ActionControlEvidenceRead              Action = "control_evidence.read"
	ActionVulnerabilityDecisionSummaryRead Action = "vulnerability_decision_summary.read"
	ActionReleaseReadinessRead             Action = "release_readiness.read"
	ActionReleaseSecuritySummaryRead       Action = "release_security_summary.read"
	ActionControlTemplatesRead             Action = "control_templates.read"
	ActionControlEvidenceLink              Action = "control_evidence.link"
)

const (
	ActionArtifactsWrite         Action = "artifacts.write"
	ActionArtifactsRead          Action = "artifacts.read"
	ActionEvidenceWrite          Action = "evidence.write"
	ActionSecurityEvidenceWrite  Action = "security_evidence.write"
	ActionEvidenceRead           Action = "evidence.read"
	ActionSBOMsRead              Action = "sboms.read"
	ActionVEXDocumentsRead       Action = "vex_documents.read"
	ActionOpenAPIContractsRead   Action = "openapi_contracts.read"
	ActionVulnerabilityScansRead Action = "vulnerability_scans.read"
	ActionEvidenceLifecycleRead  Action = "evidence_lifecycle.read"
	ActionSBOMComponentsRead     Action = "sbom_components.read"
	ActionVEXPreviewRead         Action = "vex_preview.read"
	ActionEvidenceDiffsCreate    Action = "evidence_diffs.create"
)

const (
	ActionSourceRepositoriesCreate Action = "source_repositories.create"
	ActionSourceCommitsRecord      Action = "source_commits.record"
	ActionSourceBranchesUpsert     Action = "source_branches.upsert"
	ActionPullRequestsRecord       Action = "pull_requests.record"
	ActionSourceSnapshotsRecord    Action = "source_snapshots.record"
	ActionSourceRepositoriesRead   Action = "source_repositories.read"
)

const (
	ActionEvidenceVerify                  Action = "evidence.verify"
	ActionDSSEVerify                      Action = "dsse.verify"
	ActionAuditChainVerify                Action = "audit_chain.verify"
	ActionMerkleBatchVerify               Action = "merkle_batch.verify"
	ActionMerkleCheckpointVerify          Action = "merkle_checkpoint.verify"
	ActionReleaseManifestCheckpointVerify Action = "release_manifest_checkpoint.verify"
	ActionBackupManifestVerify            Action = "backup_manifest.verify"
	ActionReleaseBundleVerify             Action = "release_bundle.verify"
	ActionCosignVerify                    Action = "cosign.verify"
	ActionArtifactSignatureVerify         Action = "artifact_signature.verify"
	ActionSubjectVerificationDispatch     Action = "subject_verification.dispatch"
	ActionArtifactSignaturesRead          Action = "artifact_signatures.read"
)

// Package report actions retain each report's credential capability while
// evaluating only its current tenant/product/release ownership coordinates.
const (
	ActionReleaseVulnerabilityPostureRead Action = "release_vulnerability_posture.read"
	ActionControlCoverageReportRead       Action = "control_coverage_report.read"
	ActionCRAReadinessReportRead          Action = "cra_readiness_report.read"
	ActionCRAVulnerabilityHandlingRead    Action = "cra_vulnerability_handling.read"
	ActionReleaseReadinessReportRead      Action = "release_readiness_report.read"
	ActionSecurityUpdateEvidenceRead      Action = "security_update_evidence.read"
	ActionIncidentReportRead              Action = "incident_report.read"
)

// Package command actions bind report output, selection, and package access
// independently even when their issued credential capabilities are shared.
const (
	ActionCRAReadinessHTMLGenerate    Action = "cra_readiness_html.generate"
	ActionPDFReportsGenerate          Action = "pdf_reports.generate"
	ActionGraphSnapshotsCreate        Action = "graph_snapshots.create"
	ActionQuestionnaireDraftsCreate   Action = "questionnaire_drafts.create"
	ActionAnswerLibraryEntriesCreate  Action = "answer_library_entries.create"
	ActionQuestionnairePackagesCreate Action = "questionnaire_packages.create"
	ActionCustomerPackagesCreate      Action = "customer_packages.create"
	ActionCustomerPackagesAccess      Action = "customer_packages.access"
	ActionPortalAccessManage          Action = "portal_access.manage"
)

// Package catalog/export actions keep metadata, selection and publication
// capabilities distinct; a read capability does not imply a write action.
const (
	ActionAnswerLibraryEntriesRead Action = "answer_library_entries.read"
	ActionPortalAccessRead         Action = "portal_access.read"
	ActionReleaseBundlesRead       Action = "release_bundles.read"
	ActionEvidenceSummariesCreate  Action = "evidence_summaries.create"
	ActionEvidenceBundlesExport    Action = "evidence_bundles.export"
	ActionReleaseBundlesCreate     Action = "release_bundles.create"
)

// Signing administration has distinct use-case actions while retaining the
// tenant-wide keys:admin credential and current-grant boundary.
const (
	ActionTrustConfigurationsManage     Action = "trust_configurations.manage"
	ActionSigningOperationsCreate       Action = "signing_operations.create"
	ActionMerkleBatchesCreate           Action = "merkle_batches.create"
	ActionTransparencyCheckpointsRecord Action = "transparency_checkpoints.record"
)

const ActionAnomalyReportsGenerate Action = "anomaly_reports.generate"

// Boundary distinguishes tenant, resolved-resource and explicit instance authority.
type Boundary uint8

const (
	TenantBoundary Boundary = iota + 1
	InstanceBoundary
	ResourceBoundary
	// CredentialBoundary is for static catalogs that expose no tenant records.
	CredentialBoundary
)

// Definition is the immutable capability and ownership boundary of an action.
type Definition struct {
	Scope    string
	Boundary Boundary
}

// DefinitionFor rejects unknown actions instead of accepting arbitrary scopes.
func DefinitionFor(action Action) (Definition, bool) {
	switch action {
	case ActionAnomalyReportsGenerate:
		return Definition{Scope: "report:read", Boundary: ResourceBoundary}, true
	case ActionTrustConfigurationsManage, ActionSigningOperationsCreate, ActionMerkleBatchesCreate, ActionTransparencyCheckpointsRecord:
		return Definition{Scope: "keys:admin", Boundary: TenantBoundary}, true
	case ActionAnswerLibraryEntriesRead, ActionPortalAccessRead:
		return Definition{Scope: "package:read", Boundary: ResourceBoundary}, true
	case ActionReleaseBundlesRead, ActionEvidenceBundlesExport:
		return Definition{Scope: "bundle:read", Boundary: ResourceBoundary}, true
	case ActionEvidenceSummariesCreate:
		return Definition{Scope: "report:read", Boundary: ResourceBoundary}, true
	case ActionReleaseBundlesCreate:
		return Definition{Scope: "bundle:write", Boundary: ResourceBoundary}, true
	case ActionCRAReadinessHTMLGenerate, ActionPDFReportsGenerate:
		return Definition{Scope: "report:read", Boundary: ResourceBoundary}, true
	case ActionGraphSnapshotsCreate:
		return Definition{Scope: "evidence:read", Boundary: ResourceBoundary}, true
	case ActionQuestionnaireDraftsCreate, ActionCustomerPackagesAccess:
		return Definition{Scope: "package:read", Boundary: ResourceBoundary}, true
	case ActionAnswerLibraryEntriesCreate, ActionQuestionnairePackagesCreate, ActionCustomerPackagesCreate, ActionPortalAccessManage:
		return Definition{Scope: "package:write", Boundary: ResourceBoundary}, true
	case ActionReleaseVulnerabilityPostureRead:
		return Definition{Scope: "security:read", Boundary: ResourceBoundary}, true
	case ActionControlCoverageReportRead, ActionCRAReadinessReportRead, ActionCRAVulnerabilityHandlingRead, ActionSecurityUpdateEvidenceRead:
		return Definition{Scope: "report:read", Boundary: ResourceBoundary}, true
	case ActionReleaseReadinessReportRead:
		return Definition{Scope: "verify:read", Boundary: ResourceBoundary}, true
	case ActionIncidentReportRead:
		return Definition{Scope: "incident:read", Boundary: ResourceBoundary}, true
	case ActionEvidenceVerify, ActionDSSEVerify, ActionAuditChainVerify, ActionMerkleBatchVerify, ActionMerkleCheckpointVerify,
		ActionReleaseManifestCheckpointVerify, ActionBackupManifestVerify, ActionReleaseBundleVerify, ActionCosignVerify,
		ActionArtifactSignatureVerify, ActionSubjectVerificationDispatch:
		return Definition{Scope: "verify:read", Boundary: ResourceBoundary}, true
	case ActionArtifactSignaturesRead:
		return Definition{Scope: "evidence:read", Boundary: ResourceBoundary}, true
	case ActionSourceRepositoriesCreate, ActionSourceCommitsRecord, ActionSourceBranchesUpsert, ActionPullRequestsRecord, ActionSourceSnapshotsRecord:
		return Definition{Scope: "source:write", Boundary: ResourceBoundary}, true
	case ActionSourceRepositoriesRead:
		return Definition{Scope: "source:read", Boundary: ResourceBoundary}, true
	case ActionAPIKeysRead, ActionAPIKeysManage, ActionRetentionPoliciesManage, ActionRetentionReportRead, ActionRetentionMarkersManage, ActionAuditLogRead, ActionTenantMetricsRead, ActionBackupGenerate:
		return Definition{Scope: "admin", Boundary: TenantBoundary}, true
	case ActionMembershipsManage, ActionRoleBindingsRead:
		return Definition{Scope: "identity:admin", Boundary: TenantBoundary}, true
	case ActionControlsRead:
		return Definition{Scope: "controls:read", Boundary: TenantBoundary}, true
	case ActionControlsManage:
		return Definition{Scope: "controls:admin", Boundary: TenantBoundary}, true
	case ActionVulnerabilityPostureRead:
		return Definition{Scope: "security:read", Boundary: TenantBoundary}, true
	case ActionControlCoverageRead, ActionReportTemplatesManage:
		return Definition{Scope: "report:read", Boundary: TenantBoundary}, true
	case ActionCollectorsRead, ActionCommercialCollectorsRead, ActionCollectorHealthRead, ActionMarketplaceCollectorsRead:
		return Definition{Scope: "collector:read", Boundary: TenantBoundary}, true
	case ActionCollectorsManage, ActionMarketplaceCollectorsManage:
		return Definition{Scope: "collector:admin", Boundary: TenantBoundary}, true
	case ActionSigningCustodyRead, ActionSigningKeysManage, ActionTransparencyMetadataPublish:
		return Definition{Scope: "keys:admin", Boundary: TenantBoundary}, true
	case ActionSigningKeysRead, ActionRetentionPoliciesRead, ActionTenantSubjectVerify:
		return Definition{Scope: "verify:read", Boundary: TenantBoundary}, true
	case ActionBundleImport:
		return Definition{Scope: "bundle:write", Boundary: TenantBoundary}, true
	case ActionQuestionnaireTemplatesManage, ActionRedactionProfilesManage:
		return Definition{Scope: "package:write", Boundary: TenantBoundary}, true
	case ActionInstanceSnapshotRead, ActionInstanceReadinessRead, ActionInstanceMetricsRead, ActionOutboxDiagnosticsRead, ActionOutboxReplay, ActionSaaSProfilesManage:
		return Definition{Scope: "instance:admin", Boundary: InstanceBoundary}, true
	case ActionProductsRead:
		return Definition{Scope: "product:read", Boundary: ResourceBoundary}, true
	case ActionProductsCreate:
		return Definition{Scope: "product:write", Boundary: TenantBoundary}, true
	case ActionProjectsRead:
		return Definition{Scope: "project:read", Boundary: ResourceBoundary}, true
	case ActionProjectsCreate:
		return Definition{Scope: "project:write", Boundary: ResourceBoundary}, true
	case ActionReleasesRead, ActionReleaseCandidatesRead:
		return Definition{Scope: "release:read", Boundary: ResourceBoundary}, true
	case ActionReleasesManage:
		return Definition{Scope: "release:write", Boundary: ResourceBoundary}, true
	case ActionBuildsRead:
		return Definition{Scope: "build:read", Boundary: ResourceBoundary}, true
	case ActionBuildsCreate:
		return Definition{Scope: "build:write", Boundary: ResourceBoundary}, true
	case ActionBuildAttestationsCreate:
		return Definition{Scope: "build:write", Boundary: ResourceBoundary}, true
	case ActionReleaseCandidatesCreate:
		return Definition{Scope: "release:write", Boundary: ResourceBoundary}, true
	case ActionEnvironmentsRead, ActionDeploymentsRead:
		return Definition{Scope: "deployment:read", Boundary: ResourceBoundary}, true
	case ActionEnvironmentsCreate, ActionDeploymentsRecord:
		return Definition{Scope: "deployment:write", Boundary: ResourceBoundary}, true
	case ActionIncidentsManage:
		return Definition{Scope: "incident:write", Boundary: ResourceBoundary}, true
	case ActionVulnerabilityDecisionsRecord:
		return Definition{Scope: "evidence:write", Boundary: ResourceBoundary}, true
	case ActionApprovalsRecord, ActionExceptionsManage:
		return Definition{Scope: "release:write", Boundary: ResourceBoundary}, true
	case ActionWaiversManage, ActionCustomPoliciesCreate:
		return Definition{Scope: "policy:write", Boundary: ResourceBoundary}, true
	case ActionVulnerabilityWorkflowsRecord:
		return Definition{Scope: "security:write", Boundary: ResourceBoundary}, true
	case ActionPolicyEvaluationsCreate:
		return Definition{Scope: "verify:read", Boundary: ResourceBoundary}, true
	case ActionCustomPoliciesEvaluate:
		return Definition{Scope: "policy:read", Boundary: ResourceBoundary}, true
	case ActionVulnerabilityDecisionsRead:
		return Definition{Scope: "evidence:read", Boundary: ResourceBoundary}, true
	case ActionExceptionsRead, ActionReleaseReadinessRead:
		return Definition{Scope: "verify:read", Boundary: ResourceBoundary}, true
	case ActionControlEvidenceRead:
		return Definition{Scope: "controls:read", Boundary: ResourceBoundary}, true
	case ActionControlEvidenceLink:
		return Definition{Scope: "controls:write", Boundary: ResourceBoundary}, true
	case ActionVulnerabilityDecisionSummaryRead, ActionReleaseSecuritySummaryRead:
		return Definition{Scope: "report:read", Boundary: ResourceBoundary}, true
	case ActionControlTemplatesRead:
		return Definition{Scope: "controls:read", Boundary: CredentialBoundary}, true
	case ActionArtifactsWrite, ActionEvidenceWrite:
		return Definition{Scope: "evidence:write", Boundary: ResourceBoundary}, true
	case ActionSecurityEvidenceWrite:
		return Definition{Scope: "security:write", Boundary: ResourceBoundary}, true
	case ActionArtifactsRead, ActionEvidenceRead, ActionSBOMsRead, ActionVEXDocumentsRead, ActionOpenAPIContractsRead,
		ActionVulnerabilityScansRead, ActionEvidenceLifecycleRead, ActionSBOMComponentsRead,
		ActionVEXPreviewRead, ActionEvidenceDiffsCreate:
		return Definition{Scope: "evidence:read", Boundary: ResourceBoundary}, true
	default:
		return Definition{}, false
	}
}
