package httpapi

const (
	operationOwnerExtension             = "x-evydence-owner"
	operationOwnerIdentityAccess        = "identity-access"
	operationOwnerReleaseCatalog        = "release-catalog"
	operationOwnerEvidenceIngestion     = "evidence-ingestion"
	operationOwnerGovernance            = "governance"
	operationOwnerCustomerDelivery      = "customer-delivery"
	operationOwnerIntegrityVerification = "integrity-verification"
	operationOwnerReleaseLedger         = "release-ledger"
	operationOwnerOperationsIncidents   = "operations-incidents"
	operationOwnerIntegrationIngestion  = "integration-ingestion"
)

// boundedContextOperationOwner records context ownership by operation id.
// Route paths are an API shape, not an application ownership boundary: paths
// within the same family can intentionally remain on different migration
// tracks while the legacy release-ledger facade is decomposed.
func boundedContextOperationOwner(operationID string) (string, bool) {
	switch operationID {
	case "createAPIKey", "listAPIKeys",
		"createOrganization", "createUser", "deactivateUser",
		"createRoleBinding", "listRoleBindings",
		"createSSOProvider", "updateSSOProviderTrustMaterial", "refreshSSOProviderOIDCTrustMaterial",
		"linkSSOIdentity", "createSSOSession", "exchangeSSOCredential",
		"revokeSSOSession", "logoutSSOSession":
		return operationOwnerIdentityAccess, true

	case "createProduct", "listProducts", "getProduct",
		"createProject", "getProject",
		"createRelease", "getRelease", "startReleaseEvidenceFlow", "freezeRelease", "approveRelease",
		"createReleaseCandidate", "listReleaseCandidates", "getReleaseCandidate",
		"promoteReleaseCandidate", "rejectReleaseCandidate",
		"registerArtifact", "getArtifact", "registerContainerImage",
		"createBuild", "getBuild", "uploadBuildAttestation":
		return operationOwnerReleaseCatalog, true

	case "uploadSecurityScan", "uploadAPISecurityScan", "uploadManualSecurityDocument",
		"uploadSPDXSBOM", "createSBOMDiff",
		"createEvidence", "listEvidence", "searchEvidence", "getEvidence",
		"supersedeEvidence", "linkEvidence", "recordEvidenceLifecycleEvent", "listEvidenceLifecycleEvents",
		"uploadSBOM", "getSBOM", "listSBOMComponents",
		"uploadVEX", "previewVEXImport", "getVEX", "getVEXImportReport",
		"uploadCycloneDXVEX", "previewCycloneDXVEXImport",
		"uploadVulnerabilityScan", "getVulnerabilityScan",
		"uploadOpenAPIContract", "getOpenAPIContract", "createOpenAPIDiff":
		return operationOwnerEvidenceIngestion, true

	case "evaluatePolicy", "listVulnerabilityDecisions", "createVulnerabilityDecision":
		return operationOwnerGovernance, true

	case "exportEvidenceBundle", "importEvidenceBundle", "createReleaseBundle":
		return operationOwnerCustomerDelivery, true

	case "verifyBuildAttestationSignature", "verifyReleaseBundle":
		return operationOwnerIntegrityVerification, true

	case "createIncident", "recordIncidentTimeline", "createRemediationTask", "createIncidentWebhookReceiver", "receiveIncidentWebhook":
		return operationOwnerOperationsIncidents, true
	case "createCollector", "recordCollectorRelease", "createCommercialCollector":
		return operationOwnerIntegrationIngestion, true

	case "createGraphSnapshot", "createEvidenceSummary",
		"getReleaseBundle", "getReleaseBundleManifest",
		"releaseSecuritySummary",
		"recordVulnerabilityWorkflow":
		return operationOwnerReleaseLedger, true

	default:
		return "", false
	}
}

func withBoundedContextOperationOwner(operationID string, extensions map[string]any) map[string]any {
	owner, ok := boundedContextOperationOwner(operationID)
	if !ok {
		return extensions
	}
	result := make(map[string]any, len(extensions)+1)
	for name, value := range extensions {
		result[name] = value
	}
	result[operationOwnerExtension] = owner
	return result
}
