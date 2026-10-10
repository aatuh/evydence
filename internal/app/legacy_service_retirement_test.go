package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestLegacyPackageGeneratorsAreAbsentFromProduction(t *testing.T) {
	retired := map[string]bool{
		"configureIdentityCommands": true, "legacyIdentityCommands": true,
		"ledgerIdentityGrantPolicy": true, "ledgerIdentityGrantTargets": true, "ledgerIdentitySessionGrants": true,
		"ledgerIdentityCanonicalHasher": true, "ledgerIdentityOIDCDiscovery": true,
		"ledgerIdentityReader": true, "ledgerIdentityTransactions": true, "ledgerIdentityTransaction": true,
		"newLedgerIdentityTransaction": true, "BootstrapTenant": true, "Authenticate": true,
		"bootstrapTenant": true, "executeTenantBootstrap": true, "commitTenantBootstrapCompatibility": true, "bootstrapContextError": true,
		"ledgerCredentialManager": true, "ledgerSessionCredentialManager": true, "hashSecret": true,
		"createAPIKeyLocked": true, "newAPIKey": true,
		"openVEXDocument": true, "openVEXStatement": true, "openVEXVulnerability": true, "openVEXProduct": true,
		"parseOpenVEX": true, "parseOpenVEXReader": true, "vexValidationError": true,
		"validDecisionStatus": true, "openVEXProductIDs": true, "decisionEvidenceIDs": true,
		"vexImportIssue": true, "vexImportPreviewAssumptions": true, "vexImportPreviewLimitations": true,
		"sortedUniqueNonEmptyStrings": true, "redactionProfileExcludesPackageSensitiveFields": true,
		"decisionStatusAffected": true, "decisionStatusNotAffected": true, "decisionStatusFixed": true,
		"decisionStatusUnderInvestigation": true,
		"controlStatusSatisfied":           true, "controlStatusPartial": true, "controlStatusMissing": true,
		"controlStatusWaived": true, "controlStatusNotApplicable": true, "controlStatusUnknown": true,
		"confidenceHigh": true, "confidenceMedium": true, "confidenceLow": true, "confidenceUnsupported": true,
		"buildRiskReadinessSnapshotLocked": true, "toRiskContextError": true, "fromRiskContextError": true,
		"ControlCoverageReportInput": true, "CRAReadinessReportInput": true,
		"craReadinessReportLocked": true, "controlCoverageReportLocked": true, "evaluateControlLocked": true,
		"controlLinksForRequirementLocked": true, "controlSubjectExistsLocked": true,
		"refsForControlEvidenceSubjectLocked": true, "controlEvidenceTimeLocked": true,
		"controlsForFrameworkLocked": true, "firstFrameworkIDLocked": true,
		"acceptedExceptionForControlLocked": true, "acceptedControlExceptionsLocked": true,
		"normalizeControlRequirements": true, "aggregateConfidence": true, "scopeMatches": true,
		"slugify": true, "cleanStrings": true,
		"activeDecisionCountForReleaseLocked": true, "hasActiveCustomerPackageLocked": true,
		"decisionSBOMContextLocked": true, "decisionSupportingRefInScopeLocked": true,
		"approvalSupportsReleaseLocked": true, "findFindingLocked": true,
		"latestDecisionForFindingLocked": true, "findingHandledLocked": true,
		"unhandledCriticalFindingsLocked": true, "unhandledFindingsBySeverityLocked": true,
		"acceptedExceptionsForReleaseLocked": true,
		"checkReleaseHasPassedBuildLocked":   true, "checkReleaseHasBuildAttestationLocked": true,
		"buildStatusPassed":        true,
		"configureReleaseCommands": true, "legacyReleaseCommands": true,
		"ledgerReleaseReader": true, "ledgerReleaseTransactions": true, "ledgerReleaseTransaction": true,
		"newLedgerReleaseTransaction": true, "ledgerReleaseCandidateReferences": true,
		"ledgerReleaseCandidateCanonicalizer": true, "ledgerBuildAttestationPayloadStager": true,
		"CreateBuildRunInput": true, "CreateReleaseCandidateInput": true, "RegisterContainerImageInput": true,
		"validateCandidateRefsLocked": true, "NewContextAuthorizer": true,
		"AuthorizeArtifactRegistration": true, "AuthorizeContainerImageRegistration": true,
		"AuthorizeProductCreation": true, "AuthorizeProjectCreation": true, "AuthorizeReleaseCreation": true,
		"authorizeCatalogCreation":   true,
		"AuthorizeReleaseTransition": true, "AuthorizeCandidateTransition": true, "authorizeStateTransition": true,
		"AuthorizeBuildCreation": true, "AuthorizeCandidateCreation": true, "AuthorizeBuildAttestationCreation": true,
		"CreateObjectRetentionPolicyInput": true,
		"CreateMerkleBatchInput":           true, "CreateTransparencyCheckpointInput": true,
		"CreateSigningProviderInput": true, "CreateDSSETrustRootInput": true, "SigningKeyRevocationInput": true,
		"CustomerPackageArchive": true, "RenderCustomerPackageArchive": true,
		"customerPackageArchive": true, "customerPackageHTMLReport": true,
		"redactionProfileToPackageContext": true,
		"packageTenantMetadataLocked":      true, "packageOrganizationMetadataLocked": true,
		"packageProductMetadata": true, "packageReleaseMetadata": true,
		"packageArtifactMetadataLocked": true, "packageReleaseArtifactIDsLocked": true,
		"packageSBOMMetadataLocked": true, "packageVulnerabilityScanMetadataLocked": true,
		"packageVEXMetadataLocked": true, "packageAPIContractMetadataLocked": true, "packageOpenAPIOperations": true,
		"packageApprovalSummariesLocked": true, "approvalBelongsToPackage": true,
		"packageExceptionSummariesLocked": true, "packageWaiverSummariesLocked": true,
		"packageAnswerLibraryMetadataLocked": true, "packageObjectLockProofsLocked": true, "packageVerifyChecks": true,
		"packageProvenanceMetadataLocked": true, "packageBuildOutputs": true, "packageOptionalTime": true,
		"packageVerificationMaterialLocked": true, "verificationMatchesReleaseLocked": true,
		"packageAuditChainSummaryLocked": true, "packageDecisionSummariesLocked": true, "profileAllowsPackageType": true,
		"sortedStringSet": true, "sortManifestMapsByID": true, "cleanExternalLabel": true,
		"builtinTemplatePacks": true, "validWaiverScope": true, "validApprovalSubject": true, "validApprovalDecision": true,
		"configurePackageCommands": true, "legacyPackageCommands": true,
		"configureEvidenceCommands": true, "legacyEvidenceCommands": true,
		"ledgerEvidenceProjectionRefresher": true, "ledgerEvidenceReader": true,
		"ledgerEvidenceTransactions": true, "ledgerEvidenceTransaction": true,
		"newLedgerEvidenceTransaction": true, "validateLedgerEvidenceScopeLocked": true,
		"ledgerEvidenceObjectIngestion": true, "ledgerEvidenceSourceObjectIngestion": true,
		"ledgerEvidencePayloadParser": true, "ledgerEvidenceLifecycleSanitizer": true,
		"validateEvidenceLinkTarget": true,
		"completeLocalVEXDecision":   true, "stageLocalVEXDecisionFailure": true,
		"processLocalVEXDecisionJob": true, "validateLocalVEXDecisionEvent": true,
		"localVEXDecisionStatement": true, "localVEXDecisionStatements": true, "localVEXDecisionKeysValid": true,
		"packageSnapshotVersion":     true,
		"ledgerPackageCanonicalizer": true, "ledgerPackageSigner": true,
		"ledgerPackageProjectionRefresher": true, "ledgerPackageReader": true,
		"ledgerPackageTransactions": true, "ledgerPackageTransaction": true,
		"newLedgerPackageTransaction":      true,
		"CreateQuestionnaireTemplateInput": true, "CreateQuestionnairePackageInput": true, "CreateQuestionnaireDraftInput": true,
		"CreateQuestionnaireTemplate": true, "AuthorizeQuestionnaireTemplateCreate": true, "cloneQuestionnaireTemplateDTO": true,
		"CreateQuestionnairePackage": true, "AuthorizeQuestionnairePackageCreate": true, "authorizeQuestionnairePackageCreateLocked": true,
		"prepareLocalQuestionnairePackage": true, "questionnairePackageToContext": true, "cloneQuestionnairePackageDTO": true,
		"CreateQuestionnaireDraft": true, "evidenceIDsForQuestionLocked": true, "questionnaireResponseForQuestionLocked": true,
		"questionnaireAnswerLibraryMatchLocked": true, "questionnaireAnswerMatchesQuestion": true, "questionnaireAnswerSpecificity": true,
		"evidenceIDsForRefsLocked":                   true,
		"CreateQuestionnaireAnswerLibraryEntryInput": true, "ListQuestionnaireAnswerLibraryInput": true,
		"CreateQuestionnaireAnswerLibraryEntry": true, "ListQuestionnaireAnswerLibrary": true,
		"validateQuestionnaireTemplateControlsLocked": true, "prepareLocalAnswerLibraryInput": true,
		"AuthorizeQuestionnaireAnswerLibraryCreate": true, "authorizeAnswerLibraryCreateLocked": true,
		"answerLibraryCitationParentsLocked": true, "answerLibraryEntryToContext": true, "cloneAnswerLibraryDTO": true,
		"CreateEvidenceSummaryInput": true, "CreateEvidenceSummary": true,
		"CreateGraphSnapshotInput": true, "CreateSaaSEditionProfileInput": true, "CreateMarketplaceCollectorInput": true,
		"CreateGraphSnapshot": true, "CreateSaaSEditionProfile": true, "CreateMarketplaceCollector": true,
		"ListMarketplaceCollectors": true, "MarketplaceCollectorHealth": true, "worseHealth": true,
		"sortMarketplaceCollectors": true, "evidenceIDsForRefsBoundedLocked": true, "evidenceMatchesRefs": true,
		"authorizeGraphSnapshotLocked": true, "AuthorizeCreateGraphSnapshot": true,
		"saasProfileInput": true, "AuthorizeCreateSaaSEditionProfile": true,
		"marketplaceCollectorInput": true, "cloneLocalMarketplaceCollector": true,
		"AuthorizeCreateMarketplaceCollector": true, "authorizeMarketplaceReferencesLocked": true,
		"CreatePDFReportPackageInput": true, "CreateSigningOperationInput": true,
		"CreatePDFReportPackage": true, "CreateSigningOperation": true,
		"AuthorizeCreatePDFReportPackage": true, "AuthorizeCreateSigningOperation": true,
		"canonicalSigningRequestHash": true, "validateSigningResult": true, "signingRequestToVerification": true, "cloneLocalSigningOperation": true,
		"signingRequestProfile": true,
		"AnomalyReportInput":    true, "GenerateAnomalyReport": true,
		"AuthorizeGenerateAnomalyReport": true, "ensureFutureSubjectLocked": true,
		"anomalyReportFromContext": true, "cloneLocalAnomalyReport": true,
		"CreatePublicTransparencyLogInput": true, "PublishPublicTransparencyLogEntryInput": true, "VerifyPublicTransparencyLogEntryInput": true,
		"CreatePublicTransparencyLog": true, "PublishPublicTransparencyLogEntry": true, "VerifyPublicTransparencyLogEntry": true,
		"verifyPublicTransparencyEntryLocked": true, "verifyRFC6962StyleProof": true, "transparencyParentHash": true, "decodeSHA256Digest": true, "validSHA256Digest": true,
		"publicTransparencyLogInput": true, "publicTransparencyPublicationInput": true,
		"AuthorizeCreatePublicTransparencyLog": true, "AuthorizePublishPublicTransparencyLogEntry": true, "publicTransparencyPublicationSourceLocked": true,
		"publicTransparencyProofInput": true, "PublicTransparencyVerificationCoreRecord": true,
		"AuthorizeVerifyPublicTransparencyLogEntry": true, "publicTransparencyVerificationSourceLocked": true,
		"AuthorizeFetchPublicTransparencyLogEntryProof": true, "publicTransparencyFetchSourceLocked": true, "FetchAndVerifyPublicTransparencyLogEntry": true,
		"VerifyProviderIdentityInput": true, "VerifyProviderIdentity": true, "verifyProviderIdentity": true,
		"localProviderVerificationReader": true, "localProviderVerificationTransactions": true, "localProviderVerificationTransaction": true,
		"UpdateSSOProviderTrustMaterialInput": true, "UpdateSSOProviderTrustMaterial": true, "RefreshSSOProviderOIDCTrustMaterial": true,
		"CreateSSOSessionInput":  true,
		"CreateSSOProviderInput": true, "LinkSSOIdentityInput": true, "ExchangeSSOCredentialInput": true,
		"CreateSSOProvider": true, "LinkSSOIdentity": true, "ExchangeSSOCredential": true,
		"CreateOrganizationInput": true, "CreateUserInput": true, "CreateRoleBindingInput": true,
		"CreateOrganization": true, "CreateUser": true, "DeactivateUser": true, "CreateRoleBinding": true,
		"collectorTypeGitHubActions": true, "collectorTypeGitLabCI": true,
		"collectorTypeGenericCI": true, "collectorTypeImportBundle": true, "collectorStatusActive": true,
		"CreateEnvironmentInput": true, "RecordDeploymentInput": true,
		"CreateLegalHoldInput": true, "CreateRetentionOverrideInput": true,
		"CreateControlFrameworkInput": true, "CreateSecurityControlInput": true, "LinkControlEvidenceInput": true,
		"UploadSecurityScanInput": true, "UploadManualSecurityDocumentInput": true,
		"CreateSBOMDiffInput": true, "CreateContractDiffInput": true,
		"CreateRedactionProfileInput": true,
		"CreateCustomerPackageInput":  true,
		"CreateReportTemplateInput":   true, "RenderReportInput": true,
		"cycloneDXVEXDocument": true, "cycloneDXVEXVulnerability": true, "cycloneDXVEXAffect": true, "cycloneDXVEXAnalysis": true, "cycloneDXVEXStatement": true,
		"parseCycloneDXVEX": true, "analyzeCycloneDXVEXStatements": true, "cycloneDXVEXAffectedRefs": true, "cyclonedxAnalysisStatus": true,
		"prepareLocalControlEvidenceLink": true, "authorizeLocalControlAdmin": true,
		"CreateIncidentInput": true, "RecordIncidentTimelineInput": true, "CreateRemediationTaskInput": true,
		"CreateIncidentWebhookReceiverInput": true, "HandleIncidentWebhookInput": true,
		"incidentWebhookTimestampTolerance": true, "incidentWebhookSignedPayload": true,
		"decodeWebhookPublicKey": true, "decodeWebhookSignature": true,
		"deploymentStatusStarted": true, "deploymentStatusSucceeded": true,
		"deploymentStatusFailed": true, "deploymentStatusRolledBack": true,
		"validDeploymentStatus": true, "validateLocalDeploymentActor": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		inspected++
		ast.Inspect(file, func(node ast.Node) bool {
			var declared string
			switch value := node.(type) {
			case *ast.TypeSpec:
				declared = value.Name.Name
			case *ast.FuncDecl:
				declared = value.Name.Name
			case *ast.ValueSpec:
				for _, id := range value.Names {
					if retired[id.Name] {
						t.Errorf("%s retains historical package value %s", name, id.Name)
					}
				}
			}
			if retired[declared] {
				t.Errorf("%s retains historical package declaration %s", name, declared)
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no production application files inspected")
	}
}

func TestLegacyReleaseFacadesAndServiceFieldAreAbsentFromProduction(t *testing.T) {
	retired := map[string]bool{"CreateProduct": true, "GetProduct": true, "CreateProject": true,
		"CreateRelease": true, "GetRelease": true, "FreezeRelease": true, "ApproveRelease": true,
		"RegisterArtifact": true, "GetArtifact": true, "CreateBuildRun": true,
		"UploadBuildAttestation": true, "CreateReleaseCandidate": true,
		"UpdateReleaseCandidateState": true, "RegisterContainerImage": true}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch v := node.(type) {
			case *ast.FuncDecl:
				if v.Recv == nil || len(v.Recv.List) != 1 || !retired[v.Name.Name] {
					break
				}
				typ := v.Recv.List[0].Type
				if ptr, ok := typ.(*ast.StarExpr); ok {
					typ = ptr.X
				}
				if id, ok := typ.(*ast.Ident); ok && id.Name == "Ledger" {
					t.Errorf("%s retains Release aggregate facade %s", entry.Name(), v.Name.Name)
				}
			case *ast.Field:
				for _, name := range v.Names {
					if name.Name == "releaseCommands" {
						t.Errorf("%s retains aggregate Release service field", entry.Name())
					}
				}
			}
			return true
		})
	}
}

func TestLegacyLedgerLeafFacadesAreAbsentFromProduction(t *testing.T) {
	retiredSummaryHelpers := map[string]bool{
		"releaseEvidenceFlowCountsLocked":                   true,
		"releaseSecurityFindingDecisionCountsLocked":        true,
		"releaseSecurityApprovalSummaryLocked":              true,
		"releaseSecurityExceptionSummaryLocked":             true,
		"presentMissingStatus":                              true,
		"sbomComponentMatches":                              true,
		"actorHasTenantWideRead":                            true,
		"evidencePageConflict":                              true,
		"unambiguousVEXMatches":                             true,
		"riskDecisionSummaryToLegacy":                       true,
		"riskSupportingRefsToLegacy":                        true,
		"customerDecisionSummary":                           true,
		"supportingRefsToRiskContext":                       true,
		"signingCustodyReviewReportFromVerificationContext": true,
		"prepareLocalSourceWrite":                           true, "localSourceInputError": true,
		"prepareLocalSourceCommit": true, "prepareLocalSourceBranch": true, "prepareLocalPullRequest": true,
		"prepareLocalSourceRepositoryCreation": true,
	}
	retired := map[string]bool{
		"VerifySubject":     true,
		"CreateEvidence":    true,
		"SupersedeEvidence": true, "LinkEvidence": true, "RecordEvidenceLifecycleEvent": true,
		"AuthorizeSupersedeEvidence": true, "AuthorizeLinkEvidence": true, "AuthorizeLifecycleEvent": true,
		"authorizeEvidenceRelationships": true,
		"AuthorizeSubjectVerification":   true, "AuthorizeDSSEVerification": true, "VerifyDSSEAttestationSignature": true,
		"AuthorizeEvidenceCreation": true, "authorizeArtifactSignatureCreationLocked": true,
		"VerifyBackupManifest":        true,
		"CreateObjectRetentionPolicy": true, "VerifyObjectRetentionPolicy": true,
		"CreateMerkleBatch": true, "CreateTransparencyCheckpoint": true, "VerifyMerkleBatch": true,
		"RotateSigningKey": true, "RevokeSigningKeyWithPolicy": true, "AuthorizeSigningKeyRevocation": true,
		"CreateSigningProvider": true, "CreateDSSETrustRoot": true, "signingProviderFromVerificationService": true,
		"ListControlFrameworkTemplatePacks": true,
		"HasTenants":                        true, "MissingEvidenceReport": true, "RevokeSigningKey": true,
		"SearchEvidence": true, "UploadAPISecurityScan": true,
		"UploadGitHubSourceSnapshot": true, "UploadGitLabSourceSnapshot": true,
		"UploadSPDXSBOM": true, "UploadBuildAttestationPayload": true,
		"ensureApprovalSubjectLocked": true, "ensureWaiverScopeLocked": true,
		"uploadSourceSnapshot": true, "sourceSnapshot": true,
		"CreateSSOSession": true, "RevokeSSOSession": true, "RevokeCurrentSSOSession": true,
		"ListRoleBindings": true,
		"CreateAPIKey":     true, "ListAPIKeys": true,
		"ReadinessStatus": true, "ReadinessDiagnostics": true, "Metrics": true,
		"InstanceAdminSnapshot": true, "OutboxOperatorDiagnostics": true, "ReplayTerminalOutboxJob": true,
		"ListProducts": true, "GetProject": true,
		"GetBuildRun": true, "GetReleaseCandidate": true, "ListReleaseCandidates": true,
		"ReleaseEvidenceFlowPlan":    true,
		"ReleaseSecuritySummary":     true,
		"VulnerabilityPostureReport": true,
		"CreateCustomPolicy":         true, "EvaluateCustomPolicy": true,
		"RecordVulnerabilityWorkflow": true, "evaluatePolicyRuleLocked": true,
		"CreateWaiver": true, "ApproveWaiver": true,
		"CreateException": true, "ApproveException": true, "CreateApprovalRecord": true,
		"ListExceptions": true, "ControlCoverageReport": true, "CRAReadinessReport": true, "CRAVulnerabilityHandlingReport": true,
		"SecurityUpdateEvidenceReport": true,
		"ReleaseReadinessReport":       true,
		"GetReleaseBundle":             true,
		"GetSBOM":                      true, "GetVulnerabilityScan": true, "GetOpenAPIContract": true,
		"ListSBOMComponents":          true,
		"ListEvidenceLifecycleEvents": true,
		"GetEvidence":                 true,
		"GetArtifactSignature":        true,
		"GetDeployment":               true,
		"ListDeploymentEnvironments":  true,
		"ListDeployments":             true,
		"CreateDeploymentEnvironment": true, "RecordDeployment": true,
		"AuthorizeEnvironmentCreation": true, "AuthorizeDeploymentRecording": true,
		"CreateArtifactSignature":                 true,
		"AuthorizeArtifactSignatureCreation":      true,
		"VerifyCosignSignature":                   true,
		"RecordCollectorRelease":                  true,
		"CollectorHealthReport":                   true,
		"CreateCollector":                         true,
		"ListCollectors":                          true,
		"CreateCommercialCollectorDefinition":     true,
		"ListCommercialCollectorDefinitions":      true,
		"ListSourceRepositories":                  true,
		"AuthorizeSourceRepositoryCreation":       true,
		"CreateSourceRepository":                  true,
		"authorizeSourceRepositoryCreationLocked": true,
		"RecordSourceCommit":                      true, "UpsertSourceBranch": true, "RecordPullRequest": true,
		"AuthorizeSourceCommitRecording": true, "AuthorizeSourceBranchUpsert": true, "AuthorizePullRequestRecording": true,
		"authorizeLocalSourceWriteLocked": true,
		"ListSigningKeys":                 true,
		"ListControlFrameworks":           true, "GetSecurityControl": true,
		"CreateControlFramework": true, "CreateSecurityControl": true, "LinkControlEvidence": true,
		"InstallControlFrameworkTemplatePack": true, "ListControlEvidence": true,
		"CRAReadinessHTMLPackage": true,
		"UploadSecurityScan":      true, "UploadManualSecurityDocument": true,
		"UploadSBOM": true, "UploadSBOMPayload": true, "UploadSPDXSBOMPayload": true,
		"UploadOpenAPIContract": true, "UploadOpenAPIContractPayload": true,
		"UploadVulnerabilityScan": true, "UploadVulnerabilityScanPayload": true,
		"UploadVEX": true, "UploadVEXPayload": true, "UploadCycloneDXVEX": true,
		"CreateRedactionProfile":        true,
		"CreateCustomerSecurityPackage": true,
		"AccessCustomerSecurityPackage": true, "SecurityReviewPackageReport": true, "ExportCustomerSecurityPackageArchive": true,
		"CreateCustomReportTemplate": true, "RenderCustomReport": true, "ImportEvidenceBundle": true,
		"AuthorizeReportTemplateCreation": true, "AuthorizeReportRendering": true, "AuthorizeBundleImport": true,
		"CreateReleaseBundle": true, "AuthorizeReleaseBundleCreation": true,
		"ExportEvidenceBundle": true, "AuthorizeEvidenceBundleExport": true,
		"CreateSBOMDiff": true, "CreateContractDiff": true,
		"AuthorizeControlFrameworkCreation": true, "AuthorizeSecurityControlCreation": true,
		"authorizeLocalControlCreationScope": true, "AuthorizeControlTemplateInstallation": true,
		"AuthorizeControlEvidenceLink": true, "authorizeControlEvidenceLinkLocked": true,
		"ListAuditLog":   true,
		"IncidentReport": true, "RetentionReport": true,
		"CreateLegalHold": true, "CreateRetentionOverride": true, "ensureRetentionScopeLocked": true,
		"CreateIncident": true, "RecordIncidentTimelineEvent": true, "CreateRemediationTask": true,
		"CreateIncidentWebhookReceiver": true, "HandleIncidentWebhook": true,
		"SigningCustodyReviewReport":         true,
		"GetVEXDocument":                     true,
		"GetVEXImportReport":                 true,
		"VulnerabilityDecisionSummaryReport": true,
		"ListVulnerabilityDecisions":         true,
		"EvaluateRelease":                    true,
		"CreateVulnerabilityDecision":        true,
		"PreviewVEXImport":                   true, "PreviewCycloneDXVEXImport": true,
		"findMatchingFindingsLocked": true, "previewOpenVEXDecisionEffectsLocked": true,
		"findCycloneDXVEXMatchingFindingsLocked": true, "previewCycloneDXVEXDecisionEffectsLocked": true,
		"previewDecisionEffectsForMatchesLocked": true,
		"ListEvidence":                           true, "ListEvidencePage": true, "SearchEvidencePage": true,
		"refreshEvidencePageAuthorization": true, "evidencePageVisibility": true,
		"validateEvidencePageProjection": true, "validatePagedParserNormalizations": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		inspected++
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.TypeSpec:
				if value.Name.Name == "Ledger" {
					if fields, ok := value.Type.(*ast.StructType); ok {
						for _, field := range fields.Fields.List {
							for _, fieldName := range field.Names {
								if fieldName.Name == "packageCommands" || fieldName.Name == "evidenceCommands" || fieldName.Name == "identityCommands" {
									t.Errorf("%s retains retired aggregate service field", name)
								}
							}
						}
					}
				}
				if value.Name.Name == "matchedFinding" {
					t.Errorf("%s retains retired aggregate matching projection", name)
				}
				if value.Name.Name == "sourceSnapshot" {
					t.Errorf("%s retains retired aggregate source snapshot schema", name)
				}
				switch value.Name.Name {
				case "CreateCustomPolicyInput", "RecordVulnerabilityWorkflowInput", "CreateWaiverInput", "CreateExceptionInput", "CreateApprovalInput", "ListSBOMComponentsInput", "ListVulnerabilityDecisionsInput", "CreateVulnerabilityDecisionInput", "AuditLogFilter", "CreateArtifactSignatureInput", "RecordCollectorReleaseInput", "VerifyCosignInput", "CreateCollectorInput", "CreateCommercialCollectorInput", "RecordCommitInput", "UpsertBranchInput", "RecordPullRequestInput", "CreateRepositoryInput":
					t.Errorf("%s retains retired aggregate input %s", name, value.Name.Name)
				}
			case *ast.FuncDecl:
				if retiredSummaryHelpers[value.Name.Name] {
					t.Errorf("%s retains retired aggregate summary helper %s", name, value.Name.Name)
				}
				if !retired[value.Name.Name] || value.Recv == nil || len(value.Recv.List) != 1 {
					break
				}
				if receiver, ok := value.Recv.List[0].Type.(*ast.StarExpr); ok {
					if identifier, ok := receiver.X.(*ast.Ident); ok && identifier.Name == "Ledger" {
						t.Errorf("%s retains retired Ledger method %s", name, value.Name.Name)
					}
				}
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no production application source inspected")
	}
}

// Native portal commands, queries and token access belong to Package services.
// Historical aggregate behavior may remain an oracle for package-local tests,
// but must not be compiled into the production application surface.
func TestLegacyPortalAggregateSurfaceIsAbsentFromProduction(t *testing.T) {
	retired := map[string]bool{
		"CreateCustomerPortalAccessInput": true, "CustomerPortalAcceptanceInput": true,
		"customerPortalFailedAccessLimit": true, "customerPortalAuditEffect": true,
		"CreateCustomerPortalAccess": true, "ListCustomerPortalAccess": true,
		"RevokeCustomerPortalAccess": true, "currentPortalPackageLocked": true,
		"AccessCustomerPortalPackage": true, "AccessCustomerPortalPackageWithAcceptance": true,
		"accessCustomerPortalPackage": true, "persistCustomerPortalAccessUpdateLocked": true,
		"ExportCustomerPortalPackageArchive": true, "ExportCustomerPortalPackageArchiveWithAcceptance": true,
		"prepareLocalPortalAccess": true, "authorizePortalWriteLocked": true,
		"AuthorizeCustomerPortalAccessCreate": true, "AuthorizeCustomerPortalAccessRevoke": true,
		"packageWithDistributionWatermark": true, "portalReviewerLabel": true, "packageDistributionWatermark": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		inspected++
		ast.Inspect(file, func(node ast.Node) bool {
			var declared string
			switch value := node.(type) {
			case *ast.FuncDecl:
				declared = value.Name.Name
			case *ast.TypeSpec:
				declared = value.Name.Name
			case *ast.ValueSpec:
				for _, identifier := range value.Names {
					if retired[identifier.Name] {
						t.Errorf("%s declares retired portal aggregate value %s", name, identifier.Name)
					}
				}
			}
			if retired[declared] {
				t.Errorf("%s declares retired portal aggregate surface %s", name, declared)
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no production application source inspected")
	}
}

// The retired wrappers merely held *Ledger and forwarded back into the same
// aggregate. They must not return as substitutes for context-owned services.
func TestLegacyLedgerServiceShellsAreRetired(t *testing.T) {
	retired := map[string]bool{
		"identityService":        true,
		"releaseEvidenceService": true,
		"packageReportService":   true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.TypeSpec:
				if retired[n.Name.Name] {
					t.Errorf("%s declares retired Ledger service shell %s", name, n.Name.Name)
				}
			case *ast.FuncDecl:
				if retired[n.Name.Name] || n.Name.Name == "NewLedger" || n.Name.Name == "ReleaseLedgerMutationFromState" {
					t.Errorf("%s declares retired Ledger helper %s", name, n.Name.Name)
				}
			case *ast.SelectorExpr:
				if retired[n.Sel.Name] {
					t.Errorf("%s calls retired Ledger service factory %s", name, n.Sel.Name)
				}
			}
			return true
		})
	}
}
