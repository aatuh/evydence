package httpapi

import (
	"errors"
	"slices"

	"github.com/aatuh/api-toolkit/v3/specs"

	"github.com/aatuh/evydence/internal/authz"
)

const routeAuthorizationExtension = "x-evydence-authorization"

// routeAuthorizationPolicy describes the required boundary; it does not grant
// authority, replace application policy, or claim behavioral test coverage.
type routeAuthorizationPolicy struct {
	Mode       string         `json:"mode"`
	Actions    []authz.Action `json:"actions,omitempty"`
	TenantRule string         `json:"tenant_rule"`
}

func actionRoutePolicy(actions ...authz.Action) routeAuthorizationPolicy {
	p := routeAuthorizationPolicy{Mode: "authenticated-principal", Actions: slices.Clone(actions)}
	if len(actions) == 0 {
		return p
	}
	definition, ok := authz.DefinitionFor(actions[0])
	if !ok {
		return p
	}
	switch definition.Boundary {
	case authz.TenantBoundary:
		p.TenantRule = "current-tenant-grant"
	case authz.InstanceBoundary:
		p.TenantRule = "explicit-instance-capability"
	case authz.ResourceBoundary:
		p.TenantRule = "resolved-tenant-resource"
	case authz.CredentialBoundary:
		p.TenantRule = "static-catalog-capability"
	case authz.SelfSessionBoundary:
		p.TenantRule = "authenticated-owner-session"
	}
	return p
}

// authorizationPolicyForOperation is deliberately closed. New routes require
// an explicit policy review, including routes without an API bearer scope.
func authorizationPolicyForOperation(id string) (routeAuthorizationPolicy, bool) {
	switch id {
	case "listAPIKeys":
		return actionRoutePolicy(authz.ActionAPIKeysRead), true
	case "createAPIKey":
		return actionRoutePolicy(authz.ActionAPIKeysManage), true
	case "createOrganization", "createUser", "deactivateUser", "createRoleBinding", "createSSOProvider", "updateSSOProviderTrustMaterial", "refreshSSOProviderOIDCTrustMaterial", "linkSSOIdentity", "createSSOSession", "revokeSSOSession", "verifyProviderIdentity":
		return actionRoutePolicy(authz.ActionMembershipsManage), true
	case "listRoleBindings":
		return actionRoutePolicy(authz.ActionRoleBindingsRead), true
	case "logoutSSOSession":
		return actionRoutePolicy(authz.ActionSSOSessionsLogout), true
	case "listControlFrameworks", "getSecurityControl":
		return actionRoutePolicy(authz.ActionControlsRead), true
	case "createControlFramework", "installControlFrameworkTemplatePack", "createSecurityControl":
		return actionRoutePolicy(authz.ActionControlsManage), true
	case "listControlFrameworkTemplatePacks":
		return actionRoutePolicy(authz.ActionControlTemplatesRead), true
	case "listControlEvidence":
		return actionRoutePolicy(authz.ActionControlEvidenceRead), true
	case "linkControlEvidence":
		return actionRoutePolicy(authz.ActionControlEvidenceLink), true
	case "listCollectors":
		return actionRoutePolicy(authz.ActionCollectorsRead), true
	case "createCollector", "recordCollectorRelease", "createCommercialCollector":
		return actionRoutePolicy(authz.ActionCollectorsManage), true
	case "collectorHealthReport":
		return actionRoutePolicy(authz.ActionCollectorHealthRead), true
	case "listCommercialCollectors":
		return actionRoutePolicy(authz.ActionCommercialCollectorsRead), true
	case "createMarketplaceCollector":
		return actionRoutePolicy(authz.ActionMarketplaceCollectorsManage), true
	case "listMarketplaceCollectors", "marketplaceCollectorHealth":
		return actionRoutePolicy(authz.ActionMarketplaceCollectorsRead), true
	case "createProduct":
		return actionRoutePolicy(authz.ActionProductsCreate), true
	case "listProducts", "getProduct":
		return actionRoutePolicy(authz.ActionProductsRead), true
	case "createProject":
		return actionRoutePolicy(authz.ActionProjectsCreate), true
	case "getProject":
		return actionRoutePolicy(authz.ActionProjectsRead), true
	case "createRelease", "freezeRelease", "approveRelease", "promoteReleaseCandidate", "rejectReleaseCandidate":
		return actionRoutePolicy(authz.ActionReleasesManage), true
	case "getRelease", "startReleaseEvidenceFlow":
		return actionRoutePolicy(authz.ActionReleasesRead), true
	case "createReleaseCandidate":
		return actionRoutePolicy(authz.ActionReleaseCandidatesCreate), true
	case "listReleaseCandidates", "getReleaseCandidate":
		return actionRoutePolicy(authz.ActionReleaseCandidatesRead), true
	case "registerArtifact", "registerContainerImage", "createArtifactSignature":
		return actionRoutePolicy(authz.ActionArtifactsWrite), true
	case "getArtifact":
		return actionRoutePolicy(authz.ActionArtifactsRead), true
	case "getArtifactSignature":
		return actionRoutePolicy(authz.ActionArtifactSignaturesRead), true
	case "createBuild":
		return actionRoutePolicy(authz.ActionBuildsCreate), true
	case "getBuild":
		return actionRoutePolicy(authz.ActionBuildsRead), true
	case "uploadBuildAttestation":
		return actionRoutePolicy(authz.ActionBuildAttestationsCreate), true
	case "uploadSPDXSBOM", "createEvidence", "supersedeEvidence", "linkEvidence", "recordEvidenceLifecycleEvent", "uploadSBOM", "uploadVEX", "uploadCycloneDXVEX", "uploadVulnerabilityScan", "uploadOpenAPIContract":
		return actionRoutePolicy(authz.ActionEvidenceWrite), true
	case "listEvidence", "searchEvidence", "getEvidence":
		return actionRoutePolicy(authz.ActionEvidenceRead), true
	case "listEvidenceLifecycleEvents":
		return actionRoutePolicy(authz.ActionEvidenceLifecycleRead), true
	case "getSBOM":
		return actionRoutePolicy(authz.ActionSBOMsRead), true
	case "listSBOMComponents":
		return actionRoutePolicy(authz.ActionSBOMComponentsRead), true
	case "previewVEXImport", "previewCycloneDXVEXImport":
		return actionRoutePolicy(authz.ActionVEXPreviewRead), true
	case "getVEX", "getVEXImportReport":
		return actionRoutePolicy(authz.ActionVEXDocumentsRead), true
	case "getVulnerabilityScan":
		return actionRoutePolicy(authz.ActionVulnerabilityScansRead), true
	case "getOpenAPIContract":
		return actionRoutePolicy(authz.ActionOpenAPIContractsRead), true
	case "createSBOMDiff", "createOpenAPIDiff":
		return actionRoutePolicy(authz.ActionEvidenceDiffsCreate), true
	case "uploadSecurityScan", "uploadAPISecurityScan", "uploadManualSecurityDocument":
		return actionRoutePolicy(authz.ActionSecurityEvidenceWrite), true
	case "createSourceRepository":
		return actionRoutePolicy(authz.ActionSourceRepositoriesCreate), true
	case "recordSourceCommit":
		return actionRoutePolicy(authz.ActionSourceCommitsRecord), true
	case "upsertSourceBranch":
		return actionRoutePolicy(authz.ActionSourceBranchesUpsert), true
	case "recordPullRequest":
		return actionRoutePolicy(authz.ActionPullRequestsRecord), true
	case "uploadGitHubSourceSnapshot", "uploadGitLabSourceSnapshot":
		return actionRoutePolicy(authz.ActionSourceSnapshotsRecord), true
	case "listSourceRepositories":
		return actionRoutePolicy(authz.ActionSourceRepositoriesRead), true
	case "createDeploymentEnvironment":
		return actionRoutePolicy(authz.ActionEnvironmentsCreate), true
	case "listDeploymentEnvironments":
		return actionRoutePolicy(authz.ActionEnvironmentsRead), true
	case "recordDeployment":
		return actionRoutePolicy(authz.ActionDeploymentsRecord), true
	case "listDeployments", "getDeployment":
		return actionRoutePolicy(authz.ActionDeploymentsRead), true
	case "createIncident", "recordIncidentTimeline", "createIncidentWebhookReceiver", "createRemediationTask":
		return actionRoutePolicy(authz.ActionIncidentsManage), true
	case "incidentReport":
		return actionRoutePolicy(authz.ActionIncidentReportRead), true
	case "createVulnerabilityDecision":
		return actionRoutePolicy(authz.ActionVulnerabilityDecisionsRecord), true
	case "listVulnerabilityDecisions":
		return actionRoutePolicy(authz.ActionVulnerabilityDecisionsRead), true
	case "vulnerabilityDecisionSummaryReport":
		return actionRoutePolicy(authz.ActionVulnerabilityDecisionSummaryRead), true
	case "recordVulnerabilityWorkflow":
		return actionRoutePolicy(authz.ActionVulnerabilityWorkflowsRecord), true
	case "createApproval":
		return actionRoutePolicy(authz.ActionApprovalsRecord), true
	case "createException", "approveException":
		return actionRoutePolicy(authz.ActionExceptionsManage), true
	case "listExceptions":
		return actionRoutePolicy(authz.ActionExceptionsRead), true
	case "createWaiver", "approveWaiver":
		return actionRoutePolicy(authz.ActionWaiversManage), true
	case "createCustomPolicy":
		return actionRoutePolicy(authz.ActionCustomPoliciesCreate), true
	case "evaluateCustomPolicy":
		return actionRoutePolicy(authz.ActionCustomPoliciesEvaluate), true
	case "evaluatePolicy":
		return actionRoutePolicy(authz.ActionPolicyEvaluationsCreate), true
	case "releaseReadinessReport":
		return actionRoutePolicy(authz.ActionReleaseReadinessRead), true
	case "releaseSecuritySummary":
		return actionRoutePolicy(authz.ActionReleaseSecuritySummaryRead), true
	case "controlCoverageReport":
		return actionRoutePolicy(authz.ActionControlCoverageReportRead), true
	case "craReadinessReport":
		return actionRoutePolicy(authz.ActionCRAReadinessReportRead), true
	case "craVulnerabilityHandlingReport":
		return actionRoutePolicy(authz.ActionCRAVulnerabilityHandlingRead), true
	case "securityUpdateEvidenceReport":
		return actionRoutePolicy(authz.ActionSecurityUpdateEvidenceRead), true
	case "craReadinessHTMLPackage":
		return actionRoutePolicy(authz.ActionCRAReadinessHTMLGenerate), true
	case "createPDFReportPackage":
		return actionRoutePolicy(authz.ActionPDFReportsGenerate), true
	case "createReportTemplate", "renderReportTemplate":
		return actionRoutePolicy(authz.ActionReportTemplatesManage), true
	case "createEvidenceSummary":
		return actionRoutePolicy(authz.ActionEvidenceSummariesCreate), true
	case "createGraphSnapshot":
		return actionRoutePolicy(authz.ActionGraphSnapshotsCreate), true
	case "generateAnomalyReport":
		return actionRoutePolicy(authz.ActionAnomalyReportsGenerate), true
	case "missingEvidenceReport":
		return actionRoutePolicy(authz.ActionReleaseReadinessReportRead), true
	case "createCustomerPackage":
		return actionRoutePolicy(authz.ActionCustomerPackagesCreate), true
	case "getCustomerPackage", "downloadCustomerPackage", "securityReviewPackageReport":
		return actionRoutePolicy(authz.ActionCustomerPackagesAccess), true
	case "createCustomerPortalAccess", "revokeCustomerPortalAccess":
		return actionRoutePolicy(authz.ActionPortalAccessManage), true
	case "listCustomerPortalAccess":
		return actionRoutePolicy(authz.ActionPortalAccessRead), true
	case "createRedactionProfile":
		return actionRoutePolicy(authz.ActionRedactionProfilesManage), true
	case "createQuestionnaireTemplate":
		return actionRoutePolicy(authz.ActionQuestionnaireTemplatesManage), true
	case "createQuestionnairePackage":
		return actionRoutePolicy(authz.ActionQuestionnairePackagesCreate), true
	case "createQuestionnaireDraft":
		return actionRoutePolicy(authz.ActionQuestionnaireDraftsCreate), true
	case "createQuestionnaireAnswerLibraryEntry":
		return actionRoutePolicy(authz.ActionAnswerLibraryEntriesCreate), true
	case "listQuestionnaireAnswerLibrary":
		return actionRoutePolicy(authz.ActionAnswerLibraryEntriesRead), true
	case "exportEvidenceBundle":
		return actionRoutePolicy(authz.ActionEvidenceBundlesExport), true
	case "importEvidenceBundle":
		return actionRoutePolicy(authz.ActionBundleImport), true
	case "createReleaseBundle":
		return actionRoutePolicy(authz.ActionReleaseBundlesCreate), true
	case "getReleaseBundle", "getReleaseBundleManifest":
		return actionRoutePolicy(authz.ActionReleaseBundlesRead), true
	case "verifyBuildAttestationSignature":
		return actionRoutePolicy(authz.ActionDSSEVerify), true
	case "verifyCosignSignature":
		return actionRoutePolicy(authz.ActionCosignVerify), true
	case "verifyReleaseBundle":
		return actionRoutePolicy(authz.ActionReleaseBundleVerify), true
	case "verifyAuditChain":
		return actionRoutePolicy(authz.ActionAuditChainVerify), true
	case "verifyMerkleBatch":
		return actionRoutePolicy(authz.ActionMerkleBatchVerify), true
	case "verifyObjectRetentionPolicy":
		return actionRoutePolicy(authz.ActionRetentionPoliciesRead), true
	case "createObjectRetentionPolicy":
		return actionRoutePolicy(authz.ActionRetentionPoliciesManage), true
	case "createLegalHold", "createRetentionOverride":
		return actionRoutePolicy(authz.ActionRetentionMarkersManage), true
	case "retentionReport":
		return actionRoutePolicy(authz.ActionRetentionReportRead), true
	case "generateBackupManifest":
		return actionRoutePolicy(authz.ActionBackupGenerate), true
	case "verifyBackupManifest":
		return actionRoutePolicy(authz.ActionBackupManifestVerify), true
	case "createMerkleBatch":
		return actionRoutePolicy(authz.ActionMerkleBatchesCreate), true
	case "createTransparencyCheckpoint":
		return actionRoutePolicy(authz.ActionTransparencyCheckpointsRecord), true
	case "createPublicTransparencyLog", "publishPublicTransparencyLogEntry", "verifyPublicTransparencyLogEntry", "fetchPublicTransparencyLogEntryProof":
		return actionRoutePolicy(authz.ActionTransparencyMetadataPublish), true
	case "signingCustodyReviewReport":
		return actionRoutePolicy(authz.ActionSigningCustodyRead), true
	case "listSigningKeys":
		return actionRoutePolicy(authz.ActionSigningKeysRead), true
	case "rotateSigningKey", "revokeSigningKey":
		return actionRoutePolicy(authz.ActionSigningKeysManage), true
	case "createDSSETrustRoot", "createSigningProvider":
		return actionRoutePolicy(authz.ActionTrustConfigurationsManage), true
	case "createSigningOperation":
		return actionRoutePolicy(authz.ActionSigningOperationsCreate), true
	case "readinessDiagnostics":
		return actionRoutePolicy(authz.ActionInstanceReadinessRead), true
	case "instanceAdminSnapshot":
		return actionRoutePolicy(authz.ActionInstanceSnapshotRead), true
	case "outboxOperatorDiagnostics":
		return actionRoutePolicy(authz.ActionOutboxDiagnosticsRead), true
	case "replayTerminalOutboxJob":
		return actionRoutePolicy(authz.ActionOutboxReplay), true
	case "createSaaSEditionProfile":
		return actionRoutePolicy(authz.ActionSaaSProfilesManage), true
	case "listAuditLog":
		return actionRoutePolicy(authz.ActionAuditLogRead), true
	case "health", "ready", "version", "openapi":
		return routeAuthorizationPolicy{Mode: "public-probe", TenantRule: "no-tenant-data"}, true
	case "receiveIncidentWebhook":
		return routeAuthorizationPolicy{Mode: "signed-webhook", TenantRule: "verified-receiver-tenant"}, true
	case "accessCustomerPortalPackage", "downloadCustomerPortalPackage", "customerPortalPackageViewForm", "customerPortalPackageView", "downloadCustomerPortalPackageView":
		return routeAuthorizationPolicy{Mode: "package-token", TenantRule: "token-bound-package"}, true
	case "exchangeSSOCredential":
		return routeAuthorizationPolicy{Mode: "verified-sso-credential", TenantRule: "verified-identity-tenant"}, true
	case "metrics":
		p := actionRoutePolicy(authz.ActionTenantMetricsRead, authz.ActionInstanceMetricsRead)
		p.TenantRule = "tenant-metrics-or-explicit-instance"
		return p, true
	case "vulnerabilityPostureReport":
		p := actionRoutePolicy(authz.ActionVulnerabilityPostureRead, authz.ActionReleaseVulnerabilityPostureRead)
		p.TenantRule = "tenant-inventory-or-resolved-release"
		return p, true
	case "verify":
		p := actionRoutePolicy(authz.ActionSubjectVerificationDispatch, authz.ActionEvidenceVerify, authz.ActionDSSEVerify, authz.ActionAuditChainVerify, authz.ActionReleaseBundleVerify, authz.ActionArtifactSignatureVerify, authz.ActionMerkleBatchVerify, authz.ActionMerkleCheckpointVerify, authz.ActionReleaseManifestCheckpointVerify, authz.ActionBackupManifestVerify)
		p.TenantRule = "resolved-subject-dispatch"
		return p, true
	default:
		return routeAuthorizationPolicy{}, false
	}
}

func validateRouteAuthorizationPolicy(op specs.Operation, p routeAuthorizationPolicy) error {
	expected, known := authorizationPolicyForOperation(op.OperationID)
	if !known || p.Mode != expected.Mode || p.TenantRule != expected.TenantRule || !slices.Equal(p.Actions, expected.Actions) {
		return errors.New("route authorization contract disagrees with operation binding")
	}
	if p.Mode == "" || p.TenantRule == "" {
		return errors.New("missing route authorization boundary")
	}
	if p.Mode != "authenticated-principal" {
		if len(p.Actions) != 0 || len(op.Security) != 0 || len(op.Scopes) != 0 {
			return errors.New("non-bearer route declares bearer authority")
		}
		switch p.Mode {
		case "public-probe", "signed-webhook", "package-token", "verified-sso-credential":
			return nil
		default:
			return errors.New("unknown route authentication boundary")
		}
	}
	if len(p.Actions) == 0 || len(op.Security) != 1 || op.Security[0].Name != "BearerAuth" {
		return errors.New("bearer route lacks action or authentication")
	}
	scopes := map[string]bool{}
	seen := map[authz.Action]bool{}
	for _, action := range p.Actions {
		definition, ok := authz.DefinitionFor(action)
		if !ok || seen[action] {
			return errors.New("unknown or duplicate route action")
		}
		seen[action] = true
		scopes[definition.Scope] = true
	}
	for _, scope := range op.Scopes {
		if !scopes[scope] {
			return errors.New("route scope disagrees with action policy")
		}
	}
	primary, _ := authz.DefinitionFor(p.Actions[0])
	if primary.Scope != "" && (len(op.Scopes) != 1 || op.Scopes[0] != primary.Scope) {
		return errors.New("route primary capability disagrees with action policy")
	}
	if len(op.Scopes) == 0 && (len(p.Actions) != 1 || p.Actions[0] != authz.ActionSSOSessionsLogout) {
		return errors.New("bearer route omits its required capability")
	}
	return nil
}

func withRouteAuthorizationPolicy(op specs.Operation) specs.Operation {
	p, ok := authorizationPolicyForOperation(op.OperationID)
	if !ok {
		return op
	}
	extensions := make(map[string]any, len(op.Extensions)+1)
	for key, value := range op.Extensions {
		extensions[key] = value
	}
	extensions[routeAuthorizationExtension] = p
	op.Extensions = extensions
	return op
}
