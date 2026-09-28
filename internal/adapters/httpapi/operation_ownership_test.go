package httpapi

import "testing"

func TestBoundedContextOperationOwnershipMetadata(t *testing.T) {
	t.Parallel()

	expected := map[string]string{
		// Identity and access remains context-owned.
		"createAPIKey":                        operationOwnerIdentityAccess,
		"listAPIKeys":                         operationOwnerIdentityAccess,
		"createOrganization":                  operationOwnerIdentityAccess,
		"createUser":                          operationOwnerIdentityAccess,
		"deactivateUser":                      operationOwnerIdentityAccess,
		"createRoleBinding":                   operationOwnerIdentityAccess,
		"listRoleBindings":                    operationOwnerIdentityAccess,
		"createSSOProvider":                   operationOwnerIdentityAccess,
		"updateSSOProviderTrustMaterial":      operationOwnerIdentityAccess,
		"refreshSSOProviderOIDCTrustMaterial": operationOwnerIdentityAccess,
		"linkSSOIdentity":                     operationOwnerIdentityAccess,
		"createSSOSession":                    operationOwnerIdentityAccess,
		"exchangeSSOCredential":               operationOwnerIdentityAccess,
		"revokeSSOSession":                    operationOwnerIdentityAccess,
		"logoutSSOSession":                    operationOwnerIdentityAccess,

		// Release catalog operations migrated by EVY-903.
		"createProduct":            operationOwnerReleaseCatalog,
		"listProducts":             operationOwnerReleaseCatalog,
		"getProduct":               operationOwnerReleaseCatalog,
		"createProject":            operationOwnerReleaseCatalog,
		"getProject":               operationOwnerReleaseCatalog,
		"createRelease":            operationOwnerReleaseCatalog,
		"getRelease":               operationOwnerReleaseCatalog,
		"startReleaseEvidenceFlow": operationOwnerReleaseCatalog,
		"freezeRelease":            operationOwnerReleaseCatalog,
		"approveRelease":           operationOwnerReleaseCatalog,
		"createReleaseCandidate":   operationOwnerReleaseCatalog,
		"listReleaseCandidates":    operationOwnerReleaseCatalog,
		"getReleaseCandidate":      operationOwnerReleaseCatalog,
		"promoteReleaseCandidate":  operationOwnerReleaseCatalog,
		"rejectReleaseCandidate":   operationOwnerReleaseCatalog,
		"registerArtifact":         operationOwnerReleaseCatalog,
		"getArtifact":              operationOwnerReleaseCatalog,
		"registerContainerImage":   operationOwnerReleaseCatalog,
		"createBuild":              operationOwnerReleaseCatalog,
		"getBuild":                 operationOwnerReleaseCatalog,
		"uploadBuildAttestation":   operationOwnerReleaseCatalog,

		// Evidence ingestion operations migrated by EVY-903.
		"uploadSecurityScan":           operationOwnerEvidenceIngestion,
		"uploadAPISecurityScan":        operationOwnerEvidenceIngestion,
		"uploadManualSecurityDocument": operationOwnerEvidenceIngestion,
		"uploadSPDXSBOM":               operationOwnerEvidenceIngestion,
		"createSBOMDiff":               operationOwnerEvidenceIngestion,
		"createEvidence":               operationOwnerEvidenceIngestion,
		"listEvidence":                 operationOwnerEvidenceIngestion,
		"searchEvidence":               operationOwnerEvidenceIngestion,
		"getEvidence":                  operationOwnerEvidenceIngestion,
		"supersedeEvidence":            operationOwnerEvidenceIngestion,
		"linkEvidence":                 operationOwnerEvidenceIngestion,
		"recordEvidenceLifecycleEvent": operationOwnerEvidenceIngestion,
		"listEvidenceLifecycleEvents":  operationOwnerEvidenceIngestion,
		"uploadSBOM":                   operationOwnerEvidenceIngestion,
		"getSBOM":                      operationOwnerEvidenceIngestion,
		"listSBOMComponents":           operationOwnerEvidenceIngestion,
		"uploadVEX":                    operationOwnerEvidenceIngestion,
		"previewVEXImport":             operationOwnerEvidenceIngestion,
		"getVEX":                       operationOwnerEvidenceIngestion,
		"getVEXImportReport":           operationOwnerEvidenceIngestion,
		"uploadCycloneDXVEX":           operationOwnerEvidenceIngestion,
		"previewCycloneDXVEXImport":    operationOwnerEvidenceIngestion,
		"uploadVulnerabilityScan":      operationOwnerEvidenceIngestion,
		"getVulnerabilityScan":         operationOwnerEvidenceIngestion,
		"uploadOpenAPIContract":        operationOwnerEvidenceIngestion,
		"getOpenAPIContract":           operationOwnerEvidenceIngestion,
		"createOpenAPIDiff":            operationOwnerEvidenceIngestion,

		// EVY-904 operations enter focused services.
		"verifyBuildAttestationSignature": operationOwnerIntegrityVerification,
		"exportEvidenceBundle":            operationOwnerCustomerDelivery,
		"importEvidenceBundle":            operationOwnerCustomerDelivery,
		"evaluatePolicy":                  operationOwnerGovernance,
		"createReleaseBundle":             operationOwnerCustomerDelivery,
		"verifyReleaseBundle":             operationOwnerIntegrityVerification,
		"listVulnerabilityDecisions":      operationOwnerGovernance,
		"createVulnerabilityDecision":     operationOwnerGovernance,

		// Query and operations routes remain on the compatibility facade.
		"createGraphSnapshot":         operationOwnerReleaseLedger,
		"createEvidenceSummary":       operationOwnerReleaseLedger,
		"getReleaseBundle":            operationOwnerReleaseLedger,
		"getReleaseBundleManifest":    operationOwnerReleaseLedger,
		"releaseSecuritySummary":      operationOwnerReleaseLedger,
		"createRemediationTask":       operationOwnerReleaseLedger,
		"recordVulnerabilityWorkflow": operationOwnerReleaseLedger,
	}

	server, _ := testServer(t)
	actual := make(map[string]string, len(expected))
	for _, route := range server.routeDefinitions() {
		owner, _ := route.op.Extensions["x-evydence-owner"].(string)
		if owner != "" {
			actual[route.op.OperationID] = owner
		}
	}

	if len(actual) != len(expected) {
		t.Fatalf("explicit owner operation count = %d, want %d: %#v", len(actual), len(expected), actual)
	}
	for operationID, want := range expected {
		if got := actual[operationID]; got != want {
			t.Errorf("operation %s owner = %q, want %q", operationID, got, want)
		}
	}

	counts := map[string]int{}
	for _, owner := range actual {
		counts[owner]++
	}
	for owner, want := range map[string]int{
		"identity-access":        15,
		"release-catalog":        21,
		"evidence-ingestion":     27,
		"release-ledger":         7,
		"customer-delivery":      3,
		"governance":             3,
		"integrity-verification": 2,
	} {
		if got := counts[owner]; got != want {
			t.Errorf("owner %s operation count = %d, want %d", owner, got, want)
		}
	}
}
