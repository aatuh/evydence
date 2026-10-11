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
	case ActionReleasesRead:
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
	case ActionEvidenceWrite:
		return Definition{Scope: "evidence:write", Boundary: ResourceBoundary}, true
	case ActionSecurityEvidenceWrite:
		return Definition{Scope: "security:write", Boundary: ResourceBoundary}, true
	case ActionEvidenceRead, ActionSBOMsRead, ActionVEXDocumentsRead, ActionOpenAPIContractsRead,
		ActionVulnerabilityScansRead, ActionEvidenceLifecycleRead, ActionSBOMComponentsRead,
		ActionVEXPreviewRead, ActionEvidenceDiffsCreate:
		return Definition{Scope: "evidence:read", Boundary: ResourceBoundary}, true
	default:
		return Definition{}, false
	}
}
