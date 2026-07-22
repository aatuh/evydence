# API Contract Matrix

This generated reference inventories Evydence `/v1` route contract precision from `openapi.yaml`.
It is a planning aid for production contract hardening; `broad` means the route still uses a shared envelope, unspecified body, or generic schema where an endpoint-specific contract should be considered.

Generated from 186 operations: 186 precise, 0 broad.

| Method | Path | Operation | Auth | Scopes | Idempotency | Params | Request | 2xx Response | Precision | Stability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GET | /v1/admin/instance | instanceAdminSnapshot | Bearer | instance:admin | - | - | - | 200:application/json:InstanceAdminSnapshotEnvelope | precise | experimental |
| GET | /v1/api-keys | listAPIKeys | Bearer | admin | - | - | - | 200:application/json:APIKeyListEnvelope | precise | supported |
| POST | /v1/api-keys | createAPIKey | Bearer | admin | required | - | application/json:CreateAPIKeyRequest | 201:application/json:APIKeyCreateEnvelope | precise | supported |
| POST | /v1/api-security-scans | uploadAPISecurityScan | Bearer | security:write | required | - | application/json:UploadSecurityScanRequest | 201:application/json:SecurityScanEnvelope | precise | experimental |
| POST | /v1/approvals | createApproval | Bearer | release:write | required | - | application/json:CreateApprovalRequest | 201:application/json:ApprovalRecordEnvelope | precise | core |
| POST | /v1/artifact-signatures | createArtifactSignature | Bearer | evidence:write | required | - | application/json:CreateArtifactSignatureRequest | 201:application/json:ArtifactSignatureEnvelope | precise | experimental |
| GET | /v1/artifact-signatures/{id} | getArtifactSignature | Bearer | evidence:read | - | path:id | - | 200:application/json:ArtifactSignatureEnvelope | precise | experimental |
| POST | /v1/artifact-signatures/{id}/verify-cosign | verifyCosignSignature | Bearer | verify:read | required | path:id | application/json:VerifyCosignSignatureRequest | 200:application/json:CosignVerificationEnvelope | precise | experimental |
| POST | /v1/artifacts | registerArtifact | Bearer | evidence:write | required | - | application/json:RegisterArtifactRequest | 201:application/json:ArtifactEnvelope | precise | core |
| GET | /v1/artifacts/{id} | getArtifact | Bearer | evidence:read | - | path:id | - | 200:application/json:ArtifactEnvelope | precise | core |
| GET | /v1/audit-chain/verify | verifyAuditChain | Bearer | verify:read | - | - | - | 200:application/json:VerificationResultEnvelope | precise | experimental |
| GET | /v1/audit-log | listAuditLog | Bearer | admin | - | query:limit, query:since, query:subject_id, query:subject_type | - | 200:application/json:AuditChainEntryListEnvelope | precise | experimental |
| POST | /v1/backup-manifests | generateBackupManifest | Bearer | admin | required | - | application/json:EmptyObject | 201:application/json:BackupManifestEnvelope | precise | experimental |
| GET | /v1/backup-manifests/{id}/verify | verifyBackupManifest | Bearer | verify:read | - | path:id | - | 200:application/json:VerificationResultEnvelope | precise | experimental |
| POST | /v1/build-attestations/{id}/verify-signature | verifyBuildAttestationSignature | Bearer | verify:read | required | path:id | application/json:EmptyObject | 200:application/json:VerificationResultEnvelope | precise | experimental |
| POST | /v1/builds | createBuild | Bearer | build:write | required | - | application/json:CreateBuildRequest | 201:application/json:BuildRunEnvelope | precise | core |
| GET | /v1/builds/{id} | getBuild | Bearer | build:read | - | path:id | - | 200:application/json:BuildRunEnvelope | precise | core |
| POST | /v1/builds/{id}/attestations | uploadBuildAttestation | Bearer | build:write | required | path:id | application/json:DSSEEnvelope | 201:application/json:BuildAttestationEnvelope | precise | core |
| GET | /v1/collectors | listCollectors | Bearer | collector:read | - | - | - | 200:application/json:CollectorListEnvelope | precise | experimental |
| POST | /v1/collectors | createCollector | Bearer | collector:admin | required | - | application/json:CreateCollectorRequest | 201:application/json:CollectorCreateEnvelope | precise | experimental |
| POST | /v1/collectors/github/source-snapshots | uploadGitHubSourceSnapshot | Bearer | source:write | required | - | application/json:SourceSnapshotRequest | 201:application/json:SourceSnapshotEnvelope | precise | experimental |
| POST | /v1/collectors/gitlab/source-snapshots | uploadGitLabSourceSnapshot | Bearer | source:write | required | - | application/json:SourceSnapshotRequest | 201:application/json:SourceSnapshotEnvelope | precise | experimental |
| GET | /v1/collectors/{id}/health | collectorHealthReport | Bearer | collector:read | - | path:id | - | 200:application/json:CollectorHealthReportEnvelope | precise | experimental |
| POST | /v1/collectors/{id}/releases | recordCollectorRelease | Bearer | collector:admin | required | path:id | application/json:RecordCollectorReleaseRequest | 201:application/json:CollectorReleaseEnvelope | precise | experimental |
| GET | /v1/commercial-collectors | listCommercialCollectors | Bearer | collector:read | - | - | - | 200:application/json:CommercialCollectorDefinitionListEnvelope | precise | experimental |
| POST | /v1/commercial-collectors | createCommercialCollector | Bearer | collector:admin | required | - | application/json:CreateCommercialCollectorRequest | 201:application/json:CommercialCollectorDefinitionEnvelope | precise | experimental |
| POST | /v1/container-images | registerContainerImage | Bearer | evidence:write | required | - | application/json:RegisterContainerImageRequest | 201:application/json:ContainerImageEnvelope | precise | experimental |
| GET | /v1/control-evidence | listControlEvidence | Bearer | controls:read | - | query:control_id, query:product_id, query:release_id | - | 200:application/json:ControlEvidenceListEnvelope | precise | experimental |
| GET | /v1/control-framework-template-packs | listControlFrameworkTemplatePacks | Bearer | controls:read | - | - | - | 200:application/json:ControlFrameworkTemplatePackListEnvelope | precise | experimental |
| POST | /v1/control-framework-template-packs/{slug}/install | installControlFrameworkTemplatePack | Bearer | controls:admin | required | path:slug | application/json:EmptyObject | 201:application/json:ControlFrameworkEnvelope | precise | experimental |
| GET | /v1/control-frameworks | listControlFrameworks | Bearer | controls:read | - | - | - | 200:application/json:ControlFrameworkListEnvelope | precise | experimental |
| POST | /v1/control-frameworks | createControlFramework | Bearer | controls:admin | required | - | application/json:CreateControlFrameworkRequest | 201:application/json:ControlFrameworkEnvelope | precise | experimental |
| POST | /v1/controls | createSecurityControl | Bearer | controls:admin | required | - | application/json:CreateSecurityControlRequest | 201:application/json:SecurityControlEnvelope | precise | experimental |
| GET | /v1/controls/{id} | getSecurityControl | Bearer | controls:read | - | path:id | - | 200:application/json:SecurityControlEnvelope | precise | experimental |
| POST | /v1/controls/{id}/evidence | linkControlEvidence | Bearer | controls:write | required | path:id | application/json:LinkControlEvidenceRequest | 201:application/json:ControlEvidenceEnvelope | precise | experimental |
| POST | /v1/custom-policies | createCustomPolicy | Bearer | policy:write | required | - | application/json:CreateCustomPolicyRequest | 201:application/json:CustomPolicyEnvelope | precise | experimental |
| POST | /v1/custom-policies/{id}/evaluate | evaluateCustomPolicy | Bearer | policy:read | required | path:id | application/json:EvaluatePolicyRequest | 201:application/json:CustomPolicyEvaluationEnvelope | precise | experimental |
| POST | /v1/customer-packages | createCustomerPackage | Bearer | package:write | required | - | application/json:CreateCustomerPackageRequest | 201:application/json:CustomerSecurityPackageEnvelope | precise | core |
| GET | /v1/customer-packages/{id} | getCustomerPackage | Bearer | package:read | - | path:id | - | 200:application/json:CustomerSecurityPackageEnvelope | precise | core |
| GET | /v1/customer-packages/{id}/download | downloadCustomerPackage | Bearer | package:read | - | path:id | - | 200:application/zip:string/binary | precise | core |
| GET | /v1/customer-portal/access | listCustomerPortalAccess | Bearer | package:read | - | query:package_id | - | 200:application/json:CustomerPortalAccessListEnvelope | precise | experimental |
| POST | /v1/customer-portal/access | createCustomerPortalAccess | Bearer | package:write | required | - | application/json:CreateCustomerPortalAccessRequest | 201:application/json:CustomerPortalAccessCreateEnvelope | precise | supported |
| POST | /v1/customer-portal/access/{id}/revoke | revokeCustomerPortalAccess | Bearer | package:write | required | path:id | application/json:EmptyObject | 200:application/json:CustomerPortalAccessEnvelope | precise | experimental |
| POST | /v1/customer-portal/package | accessCustomerPortalPackage | public | - | not required | - | application/json:CustomerPortalPackageRequest | 200:application/json:CustomerSecurityPackageEnvelope | precise | supported |
| POST | /v1/customer-portal/package/download | downloadCustomerPortalPackage | public | - | not required | - | application/json:CustomerPortalPackageRequest | 200:application/zip:string/binary | precise | supported |
| GET | /v1/customer-portal/package/view | customerPortalPackageViewForm | public | - | - | - | - | 200:text/html:string | precise | experimental |
| POST | /v1/customer-portal/package/view | customerPortalPackageView | public | - | not required | - | application/x-www-form-urlencoded:CustomerPortalPackageRequest | 200:text/html:string | precise | experimental |
| POST | /v1/customer-portal/package/view/download | downloadCustomerPortalPackageView | public | - | not required | - | application/x-www-form-urlencoded:CustomerPortalPackageRequest | 200:application/zip:string/binary | precise | experimental |
| GET | /v1/deployments | listDeployments | Bearer | deployment:read | - | query:environment_id, query:release_id | - | 200:application/json:DeploymentEventListEnvelope | precise | experimental |
| POST | /v1/deployments | recordDeployment | Bearer | deployment:write | required | - | application/json:RecordDeploymentRequest | 201:application/json:DeploymentEventEnvelope | precise | experimental |
| GET | /v1/deployments/{id} | getDeployment | Bearer | deployment:read | - | path:id | - | 200:application/json:DeploymentEventEnvelope | precise | experimental |
| POST | /v1/dsse-trust-roots | createDSSETrustRoot | Bearer | keys:admin | required | - | application/json:CreateDSSETrustRootRequest | 201:application/json:DSSETrustRootEnvelope | precise | experimental |
| GET | /v1/environments | listDeploymentEnvironments | Bearer | deployment:read | - | query:product_id | - | 200:application/json:DeploymentEnvironmentListEnvelope | precise | experimental |
| POST | /v1/environments | createDeploymentEnvironment | Bearer | deployment:write | required | - | application/json:CreateDeploymentEnvironmentRequest | 201:application/json:DeploymentEnvironmentEnvelope | precise | experimental |
| GET | /v1/evidence | listEvidence | Bearer | evidence:read | - | query:release_id, query:type | - | 200:application/json:EvidenceItemListEnvelope | precise | core |
| POST | /v1/evidence | createEvidence | Bearer | evidence:write | required | - | application/json:CreateEvidenceRequest | 201:application/json:EvidenceItemEnvelope | precise | core |
| POST | /v1/evidence-bundles | exportEvidenceBundle | Bearer | bundle:read | required | - | application/json:ExportEvidenceBundleRequest | 201:application/json:EvidenceBundleEnvelope | precise | experimental |
| POST | /v1/evidence-bundles/import | importEvidenceBundle | Bearer | bundle:write | required | - | application/json:EvidenceBundle | 201:application/json:EvidenceBundleImportEnvelope | precise | experimental |
| POST | /v1/evidence-graph-snapshots | createGraphSnapshot | Bearer | evidence:read | required | - | application/json:CreateGraphSnapshotRequest | 201:application/json:EvidenceGraphSnapshotEnvelope | precise | experimental |
| POST | /v1/evidence-summaries | createEvidenceSummary | Bearer | report:read | required | - | application/json:CreateEvidenceSummaryRequest | 201:application/json:EvidenceSummaryEnvelope | precise | experimental |
| GET | /v1/evidence/search | searchEvidence | Bearer | evidence:read | - | query:cursor, query:limit, query:product_id, query:project_id, query:release_id, query:source, query:tag, query:type | - | 200:application/json:EvidenceSearchEnvelope | precise | experimental |
| GET | /v1/evidence/{id} | getEvidence | Bearer | evidence:read | - | path:id | - | 200:application/json:EvidenceItemEnvelope | precise | core |
| GET | /v1/evidence/{id}/lifecycle-events | listEvidenceLifecycleEvents | Bearer | evidence:read | - | path:id | - | 200:application/json:EvidenceLifecycleEventListEnvelope | precise | experimental |
| POST | /v1/evidence/{id}/lifecycle-events | recordEvidenceLifecycleEvent | Bearer | evidence:write | required | path:id | application/json:RecordEvidenceLifecycleEventRequest | 201:application/json:EvidenceLifecycleEventEnvelope | precise | experimental |
| POST | /v1/evidence/{id}/link | linkEvidence | Bearer | evidence:write | required | path:id | application/json:LinkEvidenceRequest | 201:application/json:EvidenceItemEnvelope | precise | core |
| POST | /v1/evidence/{id}/supersede | supersedeEvidence | Bearer | evidence:write | required | path:id | application/json:SupersedeEvidenceRequest | 201:application/json:EvidenceItemEnvelope | precise | experimental |
| GET | /v1/exceptions | listExceptions | Bearer | verify:read | - | query:release_id | - | 200:application/json:ExceptionListEnvelope | precise | experimental |
| POST | /v1/exceptions | createException | Bearer | release:write | required | - | application/json:CreateExceptionRequest | 201:application/json:ExceptionEnvelope | precise | core |
| POST | /v1/exceptions/{id}/approve | approveException | Bearer | release:write | required | path:id | application/json:EmptyObject | 200:application/json:ExceptionEnvelope | precise | core |
| GET | /v1/health | health | public | - | - | - | - | 200:application/json:HealthStatusEnvelope | precise | supported |
| POST | /v1/incident-webhooks/{receiver_id} | receiveIncidentWebhook | public | - | not required | header:X-Evydence-Webhook-Event-ID, header:X-Evydence-Webhook-Signature, header:X-Evydence-Webhook-Timestamp, path:receiver_id | application/json:SignedIncidentWebhookPayload | 201:application/json:IncidentWebhookDeliveryEnvelope | precise | experimental |
| POST | /v1/incidents | createIncident | Bearer | incident:write | required | - | application/json:CreateIncidentRequest | 201:application/json:IncidentEnvelope | precise | experimental |
| POST | /v1/incidents/{id}/timeline | recordIncidentTimeline | Bearer | incident:write | required | path:id | application/json:RecordIncidentTimelineRequest | 201:application/json:IncidentTimelineEventEnvelope | precise | experimental |
| POST | /v1/incidents/{id}/webhook-receivers | createIncidentWebhookReceiver | Bearer | incident:write | required | path:id | application/json:CreateIncidentWebhookReceiverRequest | 201:application/json:IncidentWebhookReceiverEnvelope | precise | experimental |
| POST | /v1/legal-holds | createLegalHold | Bearer | admin | required | - | application/json:CreateLegalHoldRequest | 201:application/json:LegalHoldEnvelope | precise | experimental |
| GET | /v1/marketplace-collectors | listMarketplaceCollectors | Bearer | collector:read | - | - | - | 200:application/json:MarketplaceCollectorListEnvelope | precise | experimental |
| POST | /v1/marketplace-collectors | createMarketplaceCollector | Bearer | collector:admin | required | - | application/json:CreateMarketplaceCollectorRequest | 201:application/json:MarketplaceCollectorEnvelope | precise | experimental |
| GET | /v1/marketplace-collectors/{id}/health | marketplaceCollectorHealth | Bearer | collector:read | - | path:id | - | 200:application/json:MarketplaceCollectorHealthReportEnvelope | precise | experimental |
| POST | /v1/merkle-batches | createMerkleBatch | Bearer | keys:admin | required | - | application/json:CreateMerkleBatchRequest | 201:application/json:MerkleBatchEnvelope | precise | experimental |
| GET | /v1/merkle-batches/{id}/verify | verifyMerkleBatch | Bearer | verify:read | - | path:id | - | 200:application/json:VerificationResultEnvelope | precise | experimental |
| GET | /v1/metrics | metrics | Bearer | admin | - | - | - | 200:application/json:MetricsSnapshotEnvelope,text/plain:string | precise | supported |
| POST | /v1/object-retention-policies | createObjectRetentionPolicy | Bearer | admin | required | - | application/json:CreateObjectRetentionPolicyRequest | 201:application/json:ObjectRetentionPolicyEnvelope | precise | experimental |
| POST | /v1/object-retention-policies/{id}/verify | verifyObjectRetentionPolicy | Bearer | verify:read | required | path:id | application/json:EmptyObject | 200:application/json:ObjectRetentionPolicyEnvelope | precise | experimental |
| POST | /v1/openapi-contracts | uploadOpenAPIContract | Bearer | evidence:write | required | - | application/json:UploadOpenAPIContractRequest | 201:application/json:OpenAPIContractEnvelope | precise | experimental |
| GET | /v1/openapi-contracts/{id} | getOpenAPIContract | Bearer | evidence:read | - | path:id | - | 200:application/json:OpenAPIContractEnvelope | precise | experimental |
| POST | /v1/openapi-diffs | createOpenAPIDiff | Bearer | evidence:read | required | - | application/json:CreateOpenAPIDiffRequest | 201:application/json:ContractDiffEnvelope | precise | experimental |
| GET | /v1/openapi.json | openapi | public | - | - | - | - | 200:application/json:OpenAPIDocument | precise | supported |
| POST | /v1/organizations | createOrganization | Bearer | identity:admin | required | - | application/json:CreateOrganizationRequest | 201:application/json:OrganizationEnvelope | precise | experimental |
| POST | /v1/policies/evaluate | evaluatePolicy | Bearer | verify:read | required | - | application/json:EvaluatePolicyRequest | 201:application/json:PolicyEvaluationEnvelope | precise | experimental |
| GET | /v1/products | listProducts | Bearer | product:read | - | - | - | 200:application/json:ProductListEnvelope | precise | core |
| POST | /v1/products | createProduct | Bearer | product:write | required | - | application/json:CreateProductRequest | 201:application/json:ProductEnvelope | precise | core |
| GET | /v1/products/{id} | getProduct | Bearer | product:read | - | path:id | - | 200:application/json:ProductEnvelope | precise | core |
| POST | /v1/projects | createProject | Bearer | project:write | required | - | application/json:CreateProjectRequest | 201:application/json:ProjectEnvelope | precise | core |
| GET | /v1/projects/{id} | getProject | Bearer | project:read | - | path:id | - | 200:application/json:ProjectEnvelope | precise | core |
| POST | /v1/provider-verifications | verifyProviderIdentity | Bearer | identity:admin | required | - | application/json:VerifyProviderIdentityRequest | 201:application/json:ProviderVerificationEnvelope | precise | experimental |
| POST | /v1/public-transparency-log-entries | publishPublicTransparencyLogEntry | Bearer | keys:admin | required | - | application/json:PublishPublicTransparencyLogEntryRequest | 201:application/json:PublicTransparencyLogEntryEnvelope | precise | experimental |
| POST | /v1/public-transparency-log-entries/{id}/fetch-proof | fetchPublicTransparencyLogEntryProof | Bearer | keys:admin | required | path:id | application/json:EmptyObject | 200:application/json:PublicTransparencyLogEntryEnvelope | precise | experimental |
| POST | /v1/public-transparency-log-entries/{id}/verify | verifyPublicTransparencyLogEntry | Bearer | keys:admin | required | path:id | application/json:VerifyPublicTransparencyLogEntryRequest | 200:application/json:PublicTransparencyLogEntryEnvelope | precise | experimental |
| POST | /v1/public-transparency-logs | createPublicTransparencyLog | Bearer | keys:admin | required | - | application/json:CreatePublicTransparencyLogRequest | 201:application/json:PublicTransparencyLogEnvelope | precise | experimental |
| GET | /v1/questionnaire-answer-library | listQuestionnaireAnswerLibrary | Bearer | package:read | - | query:product_id, query:question_id, query:release_id | - | 200:application/json:QuestionnaireAnswerLibraryEntryListEnvelope | precise | experimental |
| POST | /v1/questionnaire-answer-library | createQuestionnaireAnswerLibraryEntry | Bearer | package:write | required | - | application/json:CreateQuestionnaireAnswerLibraryEntryRequest | 201:application/json:QuestionnaireAnswerLibraryEntryEnvelope | precise | experimental |
| POST | /v1/questionnaire-drafts | createQuestionnaireDraft | Bearer | package:read | required | - | application/json:CreateQuestionnaireDraftRequest | 201:application/json:QuestionnaireDraftEnvelope | precise | experimental |
| POST | /v1/questionnaire-packages | createQuestionnairePackage | Bearer | package:write | required | - | application/json:CreateQuestionnairePackageRequest | 201:application/json:QuestionnairePackageEnvelope | precise | experimental |
| POST | /v1/questionnaire-templates | createQuestionnaireTemplate | Bearer | package:write | required | - | application/json:CreateQuestionnaireTemplateRequest | 201:application/json:QuestionnaireTemplateEnvelope | precise | experimental |
| GET | /v1/ready | ready | public | - | - | - | - | 200:application/json:ReadinessStatusEnvelope | precise | supported |
| POST | /v1/redaction-profiles | createRedactionProfile | Bearer | package:write | required | - | application/json:CreateRedactionProfileRequest | 201:application/json:RedactionProfileEnvelope | precise | experimental |
| POST | /v1/release-bundles | createReleaseBundle | Bearer | bundle:write | required | - | application/json:CreateReleaseBundleRequest | 201:application/json:ReleaseBundleEnvelope | precise | core |
| GET | /v1/release-bundles/{id} | getReleaseBundle | Bearer | bundle:read | - | path:id | - | 200:application/json:ReleaseBundleEnvelope | precise | core |
| GET | /v1/release-bundles/{id}/manifest | getReleaseBundleManifest | Bearer | bundle:read | - | path:id | - | 200:application/json:ReleaseBundleManifestEnvelope | precise | core |
| GET | /v1/release-bundles/{id}/verify | verifyReleaseBundle | Bearer | verify:read | - | path:id | - | 200:application/json:VerificationResultEnvelope | precise | core |
| GET | /v1/release-candidates | listReleaseCandidates | Bearer | release:read | - | query:release_id | - | 200:application/json:ReleaseCandidateListEnvelope | precise | experimental |
| POST | /v1/release-candidates | createReleaseCandidate | Bearer | release:write | required | - | application/json:CreateReleaseCandidateRequest | 201:application/json:ReleaseCandidateEnvelope | precise | experimental |
| GET | /v1/release-candidates/{id} | getReleaseCandidate | Bearer | release:read | - | path:id | - | 200:application/json:ReleaseCandidateEnvelope | precise | experimental |
| POST | /v1/release-candidates/{id}/promote | promoteReleaseCandidate | Bearer | release:write | required | path:id | application/json:ReleaseCandidateTransitionRequest | 200:application/json:ReleaseCandidateEnvelope | precise | experimental |
| POST | /v1/release-candidates/{id}/reject | rejectReleaseCandidate | Bearer | release:write | required | path:id | application/json:ReleaseCandidateTransitionRequest | 200:application/json:ReleaseCandidateEnvelope | precise | experimental |
| POST | /v1/releases | createRelease | Bearer | release:write | required | - | application/json:CreateReleaseRequest | 201:application/json:ReleaseEnvelope | precise | core |
| GET | /v1/releases/{id} | getRelease | Bearer | release:read | - | path:id | - | 200:application/json:ReleaseEnvelope | precise | core |
| POST | /v1/releases/{id}/approve | approveRelease | Bearer | release:write | required | path:id | application/json:EmptyObject | 200:application/json:ReleaseEnvelope | precise | core |
| POST | /v1/releases/{id}/evidence-flow/start | startReleaseEvidenceFlow | Bearer | release:read | required | path:id | - | 200:application/json:ReleaseEvidenceFlowEnvelope | precise | core |
| POST | /v1/releases/{id}/freeze | freezeRelease | Bearer | release:write | required | path:id | application/json:EmptyObject | 200:application/json:ReleaseEnvelope | precise | core |
| GET | /v1/releases/{id}/security-summary | releaseSecuritySummary | Bearer | report:read | - | path:id | - | 200:application/json:ReleaseSecuritySummaryEnvelope | precise | core |
| POST | /v1/remediation-tasks | createRemediationTask | Bearer | incident:write | required | - | application/json:CreateRemediationTaskRequest | 201:application/json:RemediationTaskEnvelope | precise | experimental |
| POST | /v1/report-templates | createReportTemplate | Bearer | report:read | required | - | application/json:CreateReportTemplateRequest | 201:application/json:CustomReportTemplateEnvelope | precise | experimental |
| POST | /v1/report-templates/{id}/render | renderReportTemplate | Bearer | report:read | required | path:id | application/json:RenderReportTemplateRequest | 201:application/json:RenderedCustomReportEnvelope | precise | experimental |
| POST | /v1/reports/anomaly | generateAnomalyReport | Bearer | report:read | required | - | application/json:CreateAnomalyReportRequest | 201:application/json:AnomalyReportEnvelope | precise | experimental |
| GET | /v1/reports/control-coverage | controlCoverageReport | Bearer | report:read | - | query:framework_id, query:product_id, query:release_id | - | 200:application/json:ReadinessReportEnvelope | precise | experimental |
| GET | /v1/reports/cra-readiness | craReadinessReport | Bearer | report:read | - | query:product_id, query:release_id | - | 200:application/json:ReadinessReportEnvelope | precise | experimental |
| GET | /v1/reports/cra-readiness-html | craReadinessHTMLPackage | Bearer | report:read | - | query:product_id, query:release_id | - | 200:application/json:HTMLReportPackageEnvelope | precise | experimental |
| GET | /v1/reports/cra-vulnerability-handling | craVulnerabilityHandlingReport | Bearer | report:read | - | query:product_id, query:release_id | - | 200:application/json:CRAVulnerabilityHandlingReportEnvelope | precise | experimental |
| GET | /v1/reports/custody-review | signingCustodyReviewReport | Bearer | keys:admin | - | - | - | 200:application/json:SigningCustodyReviewReportEnvelope | precise | experimental |
| GET | /v1/reports/incident-package | incidentReport | Bearer | incident:read | - | query:incident_id | - | 200:application/json:IncidentReportEnvelope | precise | experimental |
| GET | /v1/reports/missing-evidence | missingEvidenceReport | Bearer | verify:read | - | query:release_id | - | 200:application/json:MissingEvidenceReportEnvelope | precise | experimental |
| POST | /v1/reports/pdf | createPDFReportPackage | Bearer | report:read | required | - | application/json:CreatePDFReportPackageRequest | 201:application/json:PDFReportPackageEnvelope | precise | experimental |
| GET | /v1/reports/release-readiness | releaseReadinessReport | Bearer | verify:read | - | query:release_id | - | 200:application/json:ReadinessReportEnvelope | precise | core |
| GET | /v1/reports/retention | retentionReport | Bearer | admin | - | query:scope_id, query:scope_type | - | 200:application/json:RetentionReportEnvelope | precise | experimental |
| GET | /v1/reports/security-review-package | securityReviewPackageReport | Bearer | package:read | - | query:package_id | - | 200:application/json:SecurityReviewPackageReportEnvelope | precise | experimental |
| GET | /v1/reports/security-update-evidence | securityUpdateEvidenceReport | Bearer | report:read | - | query:product_id, query:release_id | - | 200:application/json:SecurityUpdateEvidenceReportEnvelope | precise | experimental |
| GET | /v1/reports/vulnerability-decision-summary | vulnerabilityDecisionSummaryReport | Bearer | report:read | - | query:release_id | - | 200:application/json:VulnerabilityDecisionSummaryReportEnvelope | precise | experimental |
| GET | /v1/reports/vulnerability-posture | vulnerabilityPostureReport | Bearer | security:read | - | query:release_id | - | 200:application/json:VulnerabilityPostureReportEnvelope | precise | experimental |
| POST | /v1/retention-overrides | createRetentionOverride | Bearer | admin | required | - | application/json:CreateRetentionOverrideRequest | 201:application/json:RetentionOverrideEnvelope | precise | experimental |
| GET | /v1/role-bindings | listRoleBindings | Bearer | identity:admin | - | - | - | 200:application/json:RoleBindingListEnvelope | precise | experimental |
| POST | /v1/role-bindings | createRoleBinding | Bearer | identity:admin | required | - | application/json:CreateRoleBindingRequest | 201:application/json:RoleBindingEnvelope | precise | experimental |
| POST | /v1/saas/profiles | createSaaSEditionProfile | Bearer | instance:admin | required | - | application/json:CreateSaaSEditionProfileRequest | 201:application/json:SaaSEditionProfileEnvelope | precise | experimental |
| GET | /v1/sbom-components | listSBOMComponents | Bearer | evidence:read | - | query:artifact_id, query:limit, query:purl, query:query, query:release_id, query:sbom_id | - | 200:application/json:SBOMComponentRecordListEnvelope | precise | core |
| POST | /v1/sbom-diffs | createSBOMDiff | Bearer | evidence:read | required | - | application/json:CreateSBOMDiffRequest | 201:application/json:SBOMDiffEnvelope | precise | experimental |
| POST | /v1/sboms | uploadSBOM | Bearer | evidence:write | required | - | application/json:EvidenceUploadRequest | 201:application/json:SBOMEnvelope | precise | core |
| POST | /v1/sboms/spdx | uploadSPDXSBOM | Bearer | evidence:write | required | - | application/json:UploadSPDXSBOMRequest | 201:application/json:SBOMEnvelope | precise | core |
| GET | /v1/sboms/{id} | getSBOM | Bearer | evidence:read | - | path:id | - | 200:application/json:SBOMEnvelope | precise | core |
| POST | /v1/security-documents | uploadManualSecurityDocument | Bearer | security:write | required | - | application/json:UploadManualSecurityDocumentRequest | 201:application/json:ManualSecurityDocumentEnvelope | precise | experimental |
| POST | /v1/security-scans | uploadSecurityScan | Bearer | security:write | required | - | application/json:UploadSecurityScanRequest | 201:application/json:SecurityScanEnvelope | precise | experimental |
| GET | /v1/signing-keys | listSigningKeys | Bearer | verify:read | - | - | - | 200:application/json:SigningKeyListEnvelope | precise | experimental |
| POST | /v1/signing-keys/rotate | rotateSigningKey | Bearer | keys:admin | required | - | application/json:SigningKeyTransitionRequest | 201:application/json:SigningKeyEnvelope | precise | experimental |
| POST | /v1/signing-keys/{id}/revoke | revokeSigningKey | Bearer | keys:admin | required | path:id | application/json:SigningKeyTransitionRequest | 200:application/json:SigningKeyEnvelope | precise | experimental |
| POST | /v1/signing-operations | createSigningOperation | Bearer | keys:admin | required | - | application/json:CreateSigningOperationRequest | 201:application/json:SigningOperationEnvelope | precise | experimental |
| POST | /v1/signing-providers | createSigningProvider | Bearer | keys:admin | required | - | application/json:CreateSigningProviderRequest | 201:application/json:SigningProviderEnvelope | precise | experimental |
| POST | /v1/source/branches | upsertSourceBranch | Bearer | source:write | required | - | application/json:UpsertSourceBranchRequest | 201:application/json:SourceBranchEnvelope | precise | experimental |
| POST | /v1/source/commits | recordSourceCommit | Bearer | source:write | required | - | application/json:RecordSourceCommitRequest | 201:application/json:SourceCommitEnvelope | precise | experimental |
| POST | /v1/source/pull-requests | recordPullRequest | Bearer | source:write | required | - | application/json:RecordPullRequestRequest | 201:application/json:PullRequestEnvelope | precise | experimental |
| GET | /v1/source/repositories | listSourceRepositories | Bearer | source:read | - | query:project_id | - | 200:application/json:SourceRepositoryListEnvelope | precise | experimental |
| POST | /v1/source/repositories | createSourceRepository | Bearer | source:write | required | - | application/json:CreateSourceRepositoryRequest | 201:application/json:SourceRepositoryEnvelope | precise | experimental |
| POST | /v1/sso/identity-links | linkSSOIdentity | Bearer | identity:admin | required | - | application/json:LinkSSOIdentityRequest | 201:application/json:UserIdentityLinkEnvelope | precise | experimental |
| POST | /v1/sso/logout | logoutSSOSession | Bearer | - | required | - | application/json:EmptyObject | 200:application/json:SSOSessionEnvelope | precise | supported |
| POST | /v1/sso/providers | createSSOProvider | Bearer | identity:admin | required | - | application/json:CreateSSOProviderRequest | 201:application/json:SSOProviderEnvelope | precise | experimental |
| POST | /v1/sso/providers/{id}/discover-oidc | refreshSSOProviderOIDCTrustMaterial | Bearer | identity:admin | required | path:id | application/json:EmptyObject | 200:application/json:SSOProviderEnvelope | precise | experimental |
| POST | /v1/sso/providers/{id}/trust-material | updateSSOProviderTrustMaterial | Bearer | identity:admin | required | path:id | application/json:UpdateSSOProviderTrustMaterialRequest | 200:application/json:SSOProviderEnvelope | precise | experimental |
| POST | /v1/sso/session-exchanges | exchangeSSOCredential | public | - | not required | - | application/json:ExchangeSSOCredentialRequest | 201:application/json:SSOCredentialExchangeEnvelope | precise | supported |
| POST | /v1/sso/sessions | createSSOSession | Bearer | identity:admin | required | - | application/json:CreateSSOSessionRequest | 201:application/json:SSOSessionCreateEnvelope | precise | experimental |
| POST | /v1/sso/sessions/{id}/revoke | revokeSSOSession | Bearer | identity:admin | required | path:id | application/json:EmptyObject | 200:application/json:SSOSessionEnvelope | precise | experimental |
| POST | /v1/transparency-checkpoints | createTransparencyCheckpoint | Bearer | keys:admin | required | - | application/json:CreateTransparencyCheckpointRequest | 201:application/json:TransparencyCheckpointEnvelope | precise | experimental |
| POST | /v1/users | createUser | Bearer | identity:admin | required | - | application/json:CreateUserRequest | 201:application/json:HumanUserEnvelope | precise | experimental |
| POST | /v1/users/{id}/deactivate | deactivateUser | Bearer | identity:admin | required | path:id | application/json:EmptyObject | 200:application/json:HumanUserEnvelope | precise | experimental |
| POST | /v1/verify | verify | Bearer | verify:read | required | - | application/json:VerifySubjectRequest | 200:application/json:VerificationResultEnvelope | precise | core |
| GET | /v1/version | version | public | - | - | - | - | 200:application/json:VersionInfoEnvelope | precise | supported |
| POST | /v1/vex | uploadVEX | Bearer | evidence:write | required | - | application/json:EvidenceUploadRequest | 201:application/json:VEXDocumentEnvelope | precise | core |
| POST | /v1/vex/cyclonedx | uploadCycloneDXVEX | Bearer | evidence:write | required | - | application/json:EvidenceUploadRequest | 201:application/json:VEXDocumentEnvelope | precise | core |
| POST | /v1/vex/cyclonedx/preview | previewCycloneDXVEXImport | Bearer | evidence:read | not required | - | application/json:EvidenceUploadRequest | 200:application/json:VEXImportPreviewEnvelope | precise | experimental |
| POST | /v1/vex/preview | previewVEXImport | Bearer | evidence:read | not required | - | application/json:EvidenceUploadRequest | 200:application/json:VEXImportPreviewEnvelope | precise | experimental |
| GET | /v1/vex/{id} | getVEX | Bearer | evidence:read | - | path:id | - | 200:application/json:VEXDocumentEnvelope | precise | core |
| GET | /v1/vex/{id}/import-report | getVEXImportReport | Bearer | evidence:read | - | path:id | - | 200:application/json:VEXImportReportEnvelope | precise | experimental |
| GET | /v1/vulnerability-decisions | listVulnerabilityDecisions | Bearer | evidence:read | - | query:active, query:component, query:product_id, query:release_id, query:status, query:vulnerability | - | 200:application/json:VulnerabilityDecisionListEnvelope | precise | core |
| POST | /v1/vulnerability-findings/{id}/decisions | createVulnerabilityDecision | Bearer | evidence:write | required | path:id | application/json:CreateVulnerabilityDecisionRequest | 201:application/json:VulnerabilityDecisionEnvelope | precise | core |
| POST | /v1/vulnerability-findings/{id}/workflow | recordVulnerabilityWorkflow | Bearer | security:write | required | path:id | application/json:RecordVulnerabilityWorkflowRequest | 201:application/json:VulnerabilityWorkflowRecordEnvelope | precise | experimental |
| POST | /v1/vulnerability-scans | uploadVulnerabilityScan | Bearer | evidence:write | required | - | application/json:UploadVulnerabilityScanRequest | 201:application/json:VulnerabilityScanEnvelope | precise | core |
| GET | /v1/vulnerability-scans/{id} | getVulnerabilityScan | Bearer | evidence:read | - | path:id | - | 200:application/json:VulnerabilityScanEnvelope | precise | core |
| POST | /v1/waivers | createWaiver | Bearer | policy:write | required | - | application/json:CreateWaiverRequest | 201:application/json:WaiverEnvelope | precise | experimental |
| POST | /v1/waivers/{id}/approve | approveWaiver | Bearer | policy:write | required | path:id | application/json:EmptyObject | 200:application/json:WaiverEnvelope | precise | experimental |
