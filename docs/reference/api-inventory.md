# Public API Inventory

This generated reference is the complete operation-level inventory for the committed `openapi.yaml` contract. It is a compatibility-review aid, not a claim that every experimental operation is stable, production-ready, or covered by an SDK.

## Review Summary

- Operations: `189`; every public operation is represented once.
- Candidate stable core: `43` operations; review this count before any stable API promise.
- Owners, auth modes, scopes, idempotency requirements, schemas, success statuses, and error status contracts are derived from OpenAPI route metadata.

| Stability | Operations |
| --- | ---: |
| `core` | 43 |
| `experimental` | 134 |
| `supported` | 12 |

## Complete Operation Inventory

| Operation | Method | Path | Stability | Owner | Auth | Scopes | Idempotency | Request | Success | Error statuses |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| instanceAdminSnapshot | GET | `/v1/admin/instance` | `experimental` | `platform-operations` | `bearer` | instance:admin | not required | - | 200:InstanceAdminSnapshotEnvelope | 400, 401, 403, 404, 409, 422 |
| outboxOperatorDiagnostics | GET | `/v1/admin/outbox` | `experimental` | `platform-operations` | `bearer` | instance:admin | not required | - | 200:OutboxDiagnosticsEnvelope | 400, 401, 403, 404, 409, 422 |
| replayTerminalOutboxJob | POST | `/v1/admin/outbox/{id}/replay` | `experimental` | `platform-operations` | `bearer` | instance:admin | required | EmptyObject | 200:OutboxReplayEnvelope | 400, 401, 403, 404, 409, 422 |
| readinessDiagnostics | GET | `/v1/admin/readiness` | `experimental` | `platform-operations` | `bearer` | instance:admin | not required | - | 200:ReadinessDiagnosticsEnvelope | 400, 401, 403, 404, 409, 422 |
| listAPIKeys | GET | `/v1/api-keys` | `supported` | `identity-access` | `bearer` | admin | not required | - | 200:APIKeyListEnvelope | 400, 401, 403, 404, 409, 422 |
| createAPIKey | POST | `/v1/api-keys` | `supported` | `identity-access` | `bearer` | admin | required | CreateAPIKeyRequest | 201:APIKeyCreateEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadAPISecurityScan | POST | `/v1/api-security-scans` | `experimental` | `release-ledger` | `bearer` | security:write | required | UploadSecurityScanRequest | 201:SecurityScanEnvelope | 400, 401, 403, 404, 409, 422 |
| createApproval | POST | `/v1/approvals` | `core` | `governance` | `bearer` | release:write | required | CreateApprovalRequest | 201:ApprovalRecordEnvelope | 400, 401, 403, 404, 409, 422 |
| createArtifactSignature | POST | `/v1/artifact-signatures` | `experimental` | `integrity-verification` | `bearer` | evidence:write | required | CreateArtifactSignatureRequest | 201:ArtifactSignatureEnvelope | 400, 401, 403, 404, 409, 422 |
| getArtifactSignature | GET | `/v1/artifact-signatures/{id}` | `experimental` | `integrity-verification` | `bearer` | evidence:read | not required | - | 200:ArtifactSignatureEnvelope | 400, 401, 403, 404, 409, 422 |
| verifyCosignSignature | POST | `/v1/artifact-signatures/{id}/verify-cosign` | `experimental` | `integrity-verification` | `bearer` | verify:read | required | VerifyCosignSignatureRequest | 200:CosignVerificationEnvelope | 400, 401, 403, 404, 409, 422 |
| registerArtifact | POST | `/v1/artifacts` | `core` | `release-ledger` | `bearer` | evidence:write | required | RegisterArtifactRequest | 201:ArtifactEnvelope | 400, 401, 403, 404, 409, 422 |
| getArtifact | GET | `/v1/artifacts/{id}` | `core` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:ArtifactEnvelope | 400, 401, 403, 404, 409, 422 |
| verifyAuditChain | GET | `/v1/audit-chain/verify` | `experimental` | `integrity-verification` | `bearer` | verify:read | not required | - | 200:VerificationResultEnvelope | 400, 401, 403, 404, 409, 422 |
| listAuditLog | GET | `/v1/audit-log` | `experimental` | `integrity-verification` | `bearer` | admin | not required | - | 200:AuditChainEntryListEnvelope | 400, 401, 403, 404, 409, 422 |
| generateBackupManifest | POST | `/v1/backup-manifests` | `experimental` | `integrity-verification` | `bearer` | admin | required | EmptyObject | 201:BackupManifestEnvelope | 400, 401, 403, 404, 409, 422 |
| verifyBackupManifest | GET | `/v1/backup-manifests/{id}/verify` | `experimental` | `integrity-verification` | `bearer` | verify:read | not required | - | 200:VerificationResultEnvelope | 400, 401, 403, 404, 409, 422 |
| verifyBuildAttestationSignature | POST | `/v1/build-attestations/{id}/verify-signature` | `experimental` | `release-ledger` | `bearer` | verify:read | required | EmptyObject | 200:VerificationResultEnvelope | 400, 401, 403, 404, 409, 422 |
| createBuild | POST | `/v1/builds` | `core` | `release-ledger` | `bearer` | build:write | required | CreateBuildRequest | 201:BuildRunEnvelope | 400, 401, 403, 404, 409, 422 |
| getBuild | GET | `/v1/builds/{id}` | `core` | `release-ledger` | `bearer` | build:read | not required | - | 200:BuildRunEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadBuildAttestation | POST | `/v1/builds/{id}/attestations` | `core` | `release-ledger` | `bearer` | build:write | required | DSSEEnvelope | 201:BuildAttestationEnvelope | 400, 401, 403, 404, 409, 422 |
| listCollectors | GET | `/v1/collectors` | `experimental` | `integration-ingestion` | `bearer` | collector:read | not required | - | 200:CollectorListEnvelope | 400, 401, 403, 404, 409, 422 |
| createCollector | POST | `/v1/collectors` | `experimental` | `integration-ingestion` | `bearer` | collector:admin | required | CreateCollectorRequest | 201:CollectorCreateEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadGitHubSourceSnapshot | POST | `/v1/collectors/github/source-snapshots` | `experimental` | `integration-ingestion` | `bearer` | source:write | required | SourceSnapshotRequest | 201:SourceSnapshotEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadGitLabSourceSnapshot | POST | `/v1/collectors/gitlab/source-snapshots` | `experimental` | `integration-ingestion` | `bearer` | source:write | required | SourceSnapshotRequest | 201:SourceSnapshotEnvelope | 400, 401, 403, 404, 409, 422 |
| collectorHealthReport | GET | `/v1/collectors/{id}/health` | `experimental` | `integration-ingestion` | `bearer` | collector:read | not required | - | 200:CollectorHealthReportEnvelope | 400, 401, 403, 404, 409, 422 |
| recordCollectorRelease | POST | `/v1/collectors/{id}/releases` | `experimental` | `integration-ingestion` | `bearer` | collector:admin | required | RecordCollectorReleaseRequest | 201:CollectorReleaseEnvelope | 400, 401, 403, 404, 409, 422 |
| listCommercialCollectors | GET | `/v1/commercial-collectors` | `experimental` | `integration-ingestion` | `bearer` | collector:read | not required | - | 200:CommercialCollectorDefinitionListEnvelope | 400, 401, 403, 404, 409, 422 |
| createCommercialCollector | POST | `/v1/commercial-collectors` | `experimental` | `integration-ingestion` | `bearer` | collector:admin | required | CreateCommercialCollectorRequest | 201:CommercialCollectorDefinitionEnvelope | 400, 401, 403, 404, 409, 422 |
| registerContainerImage | POST | `/v1/container-images` | `experimental` | `release-ledger` | `bearer` | evidence:write | required | RegisterContainerImageRequest | 201:ContainerImageEnvelope | 400, 401, 403, 404, 409, 422 |
| listControlEvidence | GET | `/v1/control-evidence` | `experimental` | `governance` | `bearer` | controls:read | not required | - | 200:ControlEvidenceListEnvelope | 400, 401, 403, 404, 409, 422 |
| listControlFrameworkTemplatePacks | GET | `/v1/control-framework-template-packs` | `experimental` | `governance` | `bearer` | controls:read | not required | - | 200:ControlFrameworkTemplatePackListEnvelope | 400, 401, 403, 404, 409, 422 |
| installControlFrameworkTemplatePack | POST | `/v1/control-framework-template-packs/{slug}/install` | `experimental` | `governance` | `bearer` | controls:admin | required | EmptyObject | 201:ControlFrameworkEnvelope | 400, 401, 403, 404, 409, 422 |
| listControlFrameworks | GET | `/v1/control-frameworks` | `experimental` | `governance` | `bearer` | controls:read | not required | - | 200:ControlFrameworkListEnvelope | 400, 401, 403, 404, 409, 422 |
| createControlFramework | POST | `/v1/control-frameworks` | `experimental` | `governance` | `bearer` | controls:admin | required | CreateControlFrameworkRequest | 201:ControlFrameworkEnvelope | 400, 401, 403, 404, 409, 422 |
| createSecurityControl | POST | `/v1/controls` | `experimental` | `governance` | `bearer` | controls:admin | required | CreateSecurityControlRequest | 201:SecurityControlEnvelope | 400, 401, 403, 404, 409, 422 |
| getSecurityControl | GET | `/v1/controls/{id}` | `experimental` | `governance` | `bearer` | controls:read | not required | - | 200:SecurityControlEnvelope | 400, 401, 403, 404, 409, 422 |
| linkControlEvidence | POST | `/v1/controls/{id}/evidence` | `experimental` | `governance` | `bearer` | controls:write | required | LinkControlEvidenceRequest | 201:ControlEvidenceEnvelope | 400, 401, 403, 404, 409, 422 |
| createCustomPolicy | POST | `/v1/custom-policies` | `experimental` | `governance` | `bearer` | policy:write | required | CreateCustomPolicyRequest | 201:CustomPolicyEnvelope | 400, 401, 403, 404, 409, 422 |
| evaluateCustomPolicy | POST | `/v1/custom-policies/{id}/evaluate` | `experimental` | `governance` | `bearer` | policy:read | required | EvaluatePolicyRequest | 201:CustomPolicyEvaluationEnvelope | 400, 401, 403, 404, 409, 422 |
| createCustomerPackage | POST | `/v1/customer-packages` | `core` | `customer-delivery` | `bearer` | package:write | required | CreateCustomerPackageRequest | 201:CustomerSecurityPackageEnvelope | 400, 401, 403, 404, 409, 422 |
| getCustomerPackage | GET | `/v1/customer-packages/{id}` | `core` | `customer-delivery` | `bearer` | package:read | not required | - | 200:CustomerSecurityPackageEnvelope | 400, 401, 403, 404, 409, 422 |
| downloadCustomerPackage | GET | `/v1/customer-packages/{id}/download` | `core` | `customer-delivery` | `bearer` | package:read | not required | - | 200:string | 400, 401, 403, 404, 409, 422 |
| listCustomerPortalAccess | GET | `/v1/customer-portal/access` | `experimental` | `customer-delivery` | `bearer` | package:read | not required | - | 200:CustomerPortalAccessListEnvelope | 400, 401, 403, 404, 409, 422 |
| createCustomerPortalAccess | POST | `/v1/customer-portal/access` | `supported` | `customer-delivery` | `bearer` | package:write | required | CreateCustomerPortalAccessRequest | 201:CustomerPortalAccessCreateEnvelope | 400, 401, 403, 404, 409, 422 |
| revokeCustomerPortalAccess | POST | `/v1/customer-portal/access/{id}/revoke` | `experimental` | `customer-delivery` | `bearer` | package:write | required | EmptyObject | 200:CustomerPortalAccessEnvelope | 400, 401, 403, 404, 409, 422 |
| accessCustomerPortalPackage | POST | `/v1/customer-portal/package` | `supported` | `customer-delivery` | `customer-portal-token` | - | required | CustomerPortalPackageRequest | 200:CustomerSecurityPackageEnvelope | 400, 401, 403, 404, 409, 422 |
| downloadCustomerPortalPackage | POST | `/v1/customer-portal/package/download` | `supported` | `customer-delivery` | `customer-portal-token` | - | required | CustomerPortalPackageRequest | 200:string | 400, 401, 403, 404, 409, 422 |
| customerPortalPackageViewForm | GET | `/v1/customer-portal/package/view` | `experimental` | `customer-delivery` | `customer-portal-token` | - | not required | - | 200:string | 400, 401, 403, 404, 409, 422 |
| customerPortalPackageView | POST | `/v1/customer-portal/package/view` | `experimental` | `customer-delivery` | `customer-portal-token` | - | required | - | 200:string | 400, 401, 403, 404, 409, 422 |
| downloadCustomerPortalPackageView | POST | `/v1/customer-portal/package/view/download` | `experimental` | `customer-delivery` | `customer-portal-token` | - | required | - | 200:string | 400, 401, 403, 404, 409, 422 |
| listDeployments | GET | `/v1/deployments` | `experimental` | `operations-incidents` | `bearer` | deployment:read | not required | - | 200:DeploymentEventListEnvelope | 400, 401, 403, 404, 409, 422 |
| recordDeployment | POST | `/v1/deployments` | `experimental` | `operations-incidents` | `bearer` | deployment:write | required | RecordDeploymentRequest | 201:DeploymentEventEnvelope | 400, 401, 403, 404, 409, 422 |
| getDeployment | GET | `/v1/deployments/{id}` | `experimental` | `operations-incidents` | `bearer` | deployment:read | not required | - | 200:DeploymentEventEnvelope | 400, 401, 403, 404, 409, 422 |
| createDSSETrustRoot | POST | `/v1/dsse-trust-roots` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | CreateDSSETrustRootRequest | 201:DSSETrustRootEnvelope | 400, 401, 403, 404, 409, 422 |
| listDeploymentEnvironments | GET | `/v1/environments` | `experimental` | `operations-incidents` | `bearer` | deployment:read | not required | - | 200:DeploymentEnvironmentListEnvelope | 400, 401, 403, 404, 409, 422 |
| createDeploymentEnvironment | POST | `/v1/environments` | `experimental` | `operations-incidents` | `bearer` | deployment:write | required | CreateDeploymentEnvironmentRequest | 201:DeploymentEnvironmentEnvelope | 400, 401, 403, 404, 409, 422 |
| listEvidence | GET | `/v1/evidence` | `core` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:EvidenceItemListEnvelope | 400, 401, 403, 404, 409, 422 |
| createEvidence | POST | `/v1/evidence` | `core` | `release-ledger` | `bearer` | evidence:write | required | CreateEvidenceRequest | 201:EvidenceItemEnvelope | 400, 401, 403, 404, 409, 422 |
| exportEvidenceBundle | POST | `/v1/evidence-bundles` | `experimental` | `release-ledger` | `bearer` | bundle:read | required | ExportEvidenceBundleRequest | 201:EvidenceBundleEnvelope | 400, 401, 403, 404, 409, 422 |
| importEvidenceBundle | POST | `/v1/evidence-bundles/import` | `experimental` | `release-ledger` | `bearer` | bundle:write | required | EvidenceBundle | 201:EvidenceBundleImportEnvelope | 400, 401, 403, 404, 409, 422 |
| createGraphSnapshot | POST | `/v1/evidence-graph-snapshots` | `experimental` | `release-ledger` | `bearer` | evidence:read | required | CreateGraphSnapshotRequest | 201:EvidenceGraphSnapshotEnvelope | 400, 401, 403, 404, 409, 422 |
| createEvidenceSummary | POST | `/v1/evidence-summaries` | `experimental` | `release-ledger` | `bearer` | report:read | required | CreateEvidenceSummaryRequest | 201:EvidenceSummaryEnvelope | 400, 401, 403, 404, 409, 422 |
| searchEvidence | GET | `/v1/evidence/search` | `experimental` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:EvidenceSearchEnvelope | 400, 401, 403, 404, 409, 422 |
| getEvidence | GET | `/v1/evidence/{id}` | `core` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:EvidenceItemEnvelope | 400, 401, 403, 404, 409, 422 |
| listEvidenceLifecycleEvents | GET | `/v1/evidence/{id}/lifecycle-events` | `experimental` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:EvidenceLifecycleEventListEnvelope | 400, 401, 403, 404, 409, 422 |
| recordEvidenceLifecycleEvent | POST | `/v1/evidence/{id}/lifecycle-events` | `experimental` | `release-ledger` | `bearer` | evidence:write | required | RecordEvidenceLifecycleEventRequest | 201:EvidenceLifecycleEventEnvelope | 400, 401, 403, 404, 409, 422 |
| linkEvidence | POST | `/v1/evidence/{id}/link` | `core` | `release-ledger` | `bearer` | evidence:write | required | LinkEvidenceRequest | 201:EvidenceItemEnvelope | 400, 401, 403, 404, 409, 422 |
| supersedeEvidence | POST | `/v1/evidence/{id}/supersede` | `experimental` | `release-ledger` | `bearer` | evidence:write | required | SupersedeEvidenceRequest | 201:EvidenceItemEnvelope | 400, 401, 403, 404, 409, 422 |
| listExceptions | GET | `/v1/exceptions` | `experimental` | `governance` | `bearer` | verify:read | not required | - | 200:ExceptionListEnvelope | 400, 401, 403, 404, 409, 422 |
| createException | POST | `/v1/exceptions` | `core` | `governance` | `bearer` | release:write | required | CreateExceptionRequest | 201:ExceptionEnvelope | 400, 401, 403, 404, 409, 422 |
| approveException | POST | `/v1/exceptions/{id}/approve` | `core` | `governance` | `bearer` | release:write | required | EmptyObject | 200:ExceptionEnvelope | 400, 401, 403, 404, 409, 422 |
| health | GET | `/v1/health` | `supported` | `platform-operations` | `public` | - | not required | - | 200:HealthStatusEnvelope | 400, 401, 403, 404, 409, 422 |
| receiveIncidentWebhook | POST | `/v1/incident-webhooks/{receiver_id}` | `experimental` | `integration-ingestion` | `webhook-signature` | - | not required | SignedIncidentWebhookPayload | 201:IncidentWebhookDeliveryEnvelope | 400, 401, 403, 404, 409, 422 |
| createIncident | POST | `/v1/incidents` | `experimental` | `operations-incidents` | `bearer` | incident:write | required | CreateIncidentRequest | 201:IncidentEnvelope | 400, 401, 403, 404, 409, 422 |
| recordIncidentTimeline | POST | `/v1/incidents/{id}/timeline` | `experimental` | `operations-incidents` | `bearer` | incident:write | required | RecordIncidentTimelineRequest | 201:IncidentTimelineEventEnvelope | 400, 401, 403, 404, 409, 422 |
| createIncidentWebhookReceiver | POST | `/v1/incidents/{id}/webhook-receivers` | `experimental` | `operations-incidents` | `bearer` | incident:write | required | CreateIncidentWebhookReceiverRequest | 201:IncidentWebhookReceiverEnvelope | 400, 401, 403, 404, 409, 422 |
| createLegalHold | POST | `/v1/legal-holds` | `experimental` | `governance` | `bearer` | admin | required | CreateLegalHoldRequest | 201:LegalHoldEnvelope | 400, 401, 403, 404, 409, 422 |
| listMarketplaceCollectors | GET | `/v1/marketplace-collectors` | `experimental` | `integration-ingestion` | `bearer` | collector:read | not required | - | 200:MarketplaceCollectorListEnvelope | 400, 401, 403, 404, 409, 422 |
| createMarketplaceCollector | POST | `/v1/marketplace-collectors` | `experimental` | `integration-ingestion` | `bearer` | collector:admin | required | CreateMarketplaceCollectorRequest | 201:MarketplaceCollectorEnvelope | 400, 401, 403, 404, 409, 422 |
| marketplaceCollectorHealth | GET | `/v1/marketplace-collectors/{id}/health` | `experimental` | `integration-ingestion` | `bearer` | collector:read | not required | - | 200:MarketplaceCollectorHealthReportEnvelope | 400, 401, 403, 404, 409, 422 |
| createMerkleBatch | POST | `/v1/merkle-batches` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | CreateMerkleBatchRequest | 201:MerkleBatchEnvelope | 400, 401, 403, 404, 409, 422 |
| verifyMerkleBatch | GET | `/v1/merkle-batches/{id}/verify` | `experimental` | `integrity-verification` | `bearer` | verify:read | not required | - | 200:VerificationResultEnvelope | 400, 401, 403, 404, 409, 422 |
| metrics | GET | `/v1/metrics` | `supported` | `platform-operations` | `bearer` | admin | not required | - | 200:MetricsSnapshotEnvelope/string | 400, 401, 403, 404, 409, 422 |
| createObjectRetentionPolicy | POST | `/v1/object-retention-policies` | `experimental` | `governance` | `bearer` | admin | required | CreateObjectRetentionPolicyRequest | 201:ObjectRetentionPolicyEnvelope | 400, 401, 403, 404, 409, 422 |
| verifyObjectRetentionPolicy | POST | `/v1/object-retention-policies/{id}/verify` | `experimental` | `governance` | `bearer` | verify:read | required | EmptyObject | 200:ObjectRetentionPolicyEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadOpenAPIContract | POST | `/v1/openapi-contracts` | `experimental` | `release-ledger` | `bearer` | evidence:write | required | UploadOpenAPIContractRequest | 201:OpenAPIContractEnvelope | 400, 401, 403, 404, 409, 422 |
| getOpenAPIContract | GET | `/v1/openapi-contracts/{id}` | `experimental` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:OpenAPIContractEnvelope | 400, 401, 403, 404, 409, 422 |
| createOpenAPIDiff | POST | `/v1/openapi-diffs` | `experimental` | `release-ledger` | `bearer` | evidence:read | required | CreateOpenAPIDiffRequest | 201:ContractDiffEnvelope | 400, 401, 403, 404, 409, 422 |
| openapi | GET | `/v1/openapi.json` | `supported` | `platform-operations` | `public` | - | not required | - | 200:OpenAPIDocument | 400, 401, 403, 404, 409, 422 |
| createOrganization | POST | `/v1/organizations` | `experimental` | `identity-access` | `bearer` | identity:admin | required | CreateOrganizationRequest | 201:OrganizationEnvelope | 400, 401, 403, 404, 409, 422 |
| evaluatePolicy | POST | `/v1/policies/evaluate` | `experimental` | `release-ledger` | `bearer` | verify:read | required | EvaluatePolicyRequest | 201:PolicyEvaluationEnvelope | 400, 401, 403, 404, 409, 422 |
| listProducts | GET | `/v1/products` | `core` | `release-ledger` | `bearer` | product:read | not required | - | 200:ProductListEnvelope | 400, 401, 403, 404, 409, 422 |
| createProduct | POST | `/v1/products` | `core` | `release-ledger` | `bearer` | product:write | required | CreateProductRequest | 201:ProductEnvelope | 400, 401, 403, 404, 409, 422 |
| getProduct | GET | `/v1/products/{id}` | `core` | `release-ledger` | `bearer` | product:read | not required | - | 200:ProductEnvelope | 400, 401, 403, 404, 409, 422 |
| createProject | POST | `/v1/projects` | `core` | `release-ledger` | `bearer` | project:write | required | CreateProjectRequest | 201:ProjectEnvelope | 400, 401, 403, 404, 409, 422 |
| getProject | GET | `/v1/projects/{id}` | `core` | `release-ledger` | `bearer` | project:read | not required | - | 200:ProjectEnvelope | 400, 401, 403, 404, 409, 422 |
| verifyProviderIdentity | POST | `/v1/provider-verifications` | `experimental` | `integrity-verification` | `bearer` | identity:admin | required | VerifyProviderIdentityRequest | 201:ProviderVerificationEnvelope | 400, 401, 403, 404, 409, 422 |
| publishPublicTransparencyLogEntry | POST | `/v1/public-transparency-log-entries` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | PublishPublicTransparencyLogEntryRequest | 201:PublicTransparencyLogEntryEnvelope | 400, 401, 403, 404, 409, 422 |
| fetchPublicTransparencyLogEntryProof | POST | `/v1/public-transparency-log-entries/{id}/fetch-proof` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | EmptyObject | 200:PublicTransparencyLogEntryEnvelope | 400, 401, 403, 404, 409, 422 |
| verifyPublicTransparencyLogEntry | POST | `/v1/public-transparency-log-entries/{id}/verify` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | VerifyPublicTransparencyLogEntryRequest | 200:PublicTransparencyLogEntryEnvelope | 400, 401, 403, 404, 409, 422 |
| createPublicTransparencyLog | POST | `/v1/public-transparency-logs` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | CreatePublicTransparencyLogRequest | 201:PublicTransparencyLogEnvelope | 400, 401, 403, 404, 409, 422 |
| listQuestionnaireAnswerLibrary | GET | `/v1/questionnaire-answer-library` | `experimental` | `governance` | `bearer` | package:read | not required | - | 200:QuestionnaireAnswerLibraryEntryListEnvelope | 400, 401, 403, 404, 409, 422 |
| createQuestionnaireAnswerLibraryEntry | POST | `/v1/questionnaire-answer-library` | `experimental` | `governance` | `bearer` | package:write | required | CreateQuestionnaireAnswerLibraryEntryRequest | 201:QuestionnaireAnswerLibraryEntryEnvelope | 400, 401, 403, 404, 409, 422 |
| createQuestionnaireDraft | POST | `/v1/questionnaire-drafts` | `experimental` | `governance` | `bearer` | package:read | required | CreateQuestionnaireDraftRequest | 201:QuestionnaireDraftEnvelope | 400, 401, 403, 404, 409, 422 |
| createQuestionnairePackage | POST | `/v1/questionnaire-packages` | `experimental` | `governance` | `bearer` | package:write | required | CreateQuestionnairePackageRequest | 201:QuestionnairePackageEnvelope | 400, 401, 403, 404, 409, 422 |
| createQuestionnaireTemplate | POST | `/v1/questionnaire-templates` | `experimental` | `governance` | `bearer` | package:write | required | CreateQuestionnaireTemplateRequest | 201:QuestionnaireTemplateEnvelope | 400, 401, 403, 404, 409, 422 |
| ready | GET | `/v1/ready` | `supported` | `platform-operations` | `public` | - | not required | - | 200:ReadinessStatusEnvelope | 400, 401, 403, 404, 409, 422, 503 |
| createRedactionProfile | POST | `/v1/redaction-profiles` | `experimental` | `customer-delivery` | `bearer` | package:write | required | CreateRedactionProfileRequest | 201:RedactionProfileEnvelope | 400, 401, 403, 404, 409, 422 |
| createReleaseBundle | POST | `/v1/release-bundles` | `core` | `release-ledger` | `bearer` | bundle:write | required | CreateReleaseBundleRequest | 201:ReleaseBundleEnvelope | 400, 401, 403, 404, 409, 422 |
| getReleaseBundle | GET | `/v1/release-bundles/{id}` | `core` | `release-ledger` | `bearer` | bundle:read | not required | - | 200:ReleaseBundleEnvelope | 400, 401, 403, 404, 409, 422 |
| getReleaseBundleManifest | GET | `/v1/release-bundles/{id}/manifest` | `core` | `release-ledger` | `bearer` | bundle:read | not required | - | 200:ReleaseBundleManifestEnvelope | 400, 401, 403, 404, 409, 422 |
| verifyReleaseBundle | GET | `/v1/release-bundles/{id}/verify` | `core` | `release-ledger` | `bearer` | verify:read | not required | - | 200:VerificationResultEnvelope | 400, 401, 403, 404, 409, 422 |
| listReleaseCandidates | GET | `/v1/release-candidates` | `experimental` | `release-ledger` | `bearer` | release:read | not required | - | 200:ReleaseCandidateListEnvelope | 400, 401, 403, 404, 409, 422 |
| createReleaseCandidate | POST | `/v1/release-candidates` | `experimental` | `release-ledger` | `bearer` | release:write | required | CreateReleaseCandidateRequest | 201:ReleaseCandidateEnvelope | 400, 401, 403, 404, 409, 422 |
| getReleaseCandidate | GET | `/v1/release-candidates/{id}` | `experimental` | `release-ledger` | `bearer` | release:read | not required | - | 200:ReleaseCandidateEnvelope | 400, 401, 403, 404, 409, 422 |
| promoteReleaseCandidate | POST | `/v1/release-candidates/{id}/promote` | `experimental` | `release-ledger` | `bearer` | release:write | required | ReleaseCandidateTransitionRequest | 200:ReleaseCandidateEnvelope | 400, 401, 403, 404, 409, 422 |
| rejectReleaseCandidate | POST | `/v1/release-candidates/{id}/reject` | `experimental` | `release-ledger` | `bearer` | release:write | required | ReleaseCandidateTransitionRequest | 200:ReleaseCandidateEnvelope | 400, 401, 403, 404, 409, 422 |
| createRelease | POST | `/v1/releases` | `core` | `release-ledger` | `bearer` | release:write | required | CreateReleaseRequest | 201:ReleaseEnvelope | 400, 401, 403, 404, 409, 422 |
| getRelease | GET | `/v1/releases/{id}` | `core` | `release-ledger` | `bearer` | release:read | not required | - | 200:ReleaseEnvelope | 400, 401, 403, 404, 409, 422 |
| approveRelease | POST | `/v1/releases/{id}/approve` | `core` | `release-ledger` | `bearer` | release:write | required | EmptyObject | 200:ReleaseEnvelope | 400, 401, 403, 404, 409, 422 |
| startReleaseEvidenceFlow | POST | `/v1/releases/{id}/evidence-flow/start` | `core` | `release-ledger` | `bearer` | release:read | required | - | 200:ReleaseEvidenceFlowEnvelope | 400, 401, 403, 404, 409, 422 |
| freezeRelease | POST | `/v1/releases/{id}/freeze` | `core` | `release-ledger` | `bearer` | release:write | required | EmptyObject | 200:ReleaseEnvelope | 400, 401, 403, 404, 409, 422 |
| releaseSecuritySummary | GET | `/v1/releases/{id}/security-summary` | `core` | `release-ledger` | `bearer` | report:read | not required | - | 200:ReleaseSecuritySummaryEnvelope | 400, 401, 403, 404, 409, 422 |
| createRemediationTask | POST | `/v1/remediation-tasks` | `experimental` | `release-ledger` | `bearer` | incident:write | required | CreateRemediationTaskRequest | 201:RemediationTaskEnvelope | 400, 401, 403, 404, 409, 422 |
| createReportTemplate | POST | `/v1/report-templates` | `experimental` | `reporting` | `bearer` | report:read | required | CreateReportTemplateRequest | 201:CustomReportTemplateEnvelope | 400, 401, 403, 404, 409, 422 |
| renderReportTemplate | POST | `/v1/report-templates/{id}/render` | `experimental` | `reporting` | `bearer` | report:read | required | RenderReportTemplateRequest | 201:RenderedCustomReportEnvelope | 400, 401, 403, 404, 409, 422 |
| generateAnomalyReport | POST | `/v1/reports/anomaly` | `experimental` | `reporting` | `bearer` | report:read | required | CreateAnomalyReportRequest | 201:AnomalyReportEnvelope | 400, 401, 403, 404, 409, 422 |
| controlCoverageReport | GET | `/v1/reports/control-coverage` | `experimental` | `reporting` | `bearer` | report:read | not required | - | 200:ReadinessReportEnvelope | 400, 401, 403, 404, 409, 422 |
| craReadinessReport | GET | `/v1/reports/cra-readiness` | `experimental` | `reporting` | `bearer` | report:read | not required | - | 200:ReadinessReportEnvelope | 400, 401, 403, 404, 409, 422 |
| craReadinessHTMLPackage | GET | `/v1/reports/cra-readiness-html` | `experimental` | `reporting` | `bearer` | report:read | not required | - | 200:HTMLReportPackageEnvelope | 400, 401, 403, 404, 409, 422 |
| craVulnerabilityHandlingReport | GET | `/v1/reports/cra-vulnerability-handling` | `experimental` | `reporting` | `bearer` | report:read | not required | - | 200:CRAVulnerabilityHandlingReportEnvelope | 400, 401, 403, 404, 409, 422 |
| signingCustodyReviewReport | GET | `/v1/reports/custody-review` | `experimental` | `reporting` | `bearer` | keys:admin | not required | - | 200:SigningCustodyReviewReportEnvelope | 400, 401, 403, 404, 409, 422 |
| incidentReport | GET | `/v1/reports/incident-package` | `experimental` | `reporting` | `bearer` | incident:read | not required | - | 200:IncidentReportEnvelope | 400, 401, 403, 404, 409, 422 |
| missingEvidenceReport | GET | `/v1/reports/missing-evidence` | `experimental` | `reporting` | `bearer` | verify:read | not required | - | 200:MissingEvidenceReportEnvelope | 400, 401, 403, 404, 409, 422 |
| createPDFReportPackage | POST | `/v1/reports/pdf` | `experimental` | `reporting` | `bearer` | report:read | required | CreatePDFReportPackageRequest | 201:PDFReportPackageEnvelope | 400, 401, 403, 404, 409, 422 |
| releaseReadinessReport | GET | `/v1/reports/release-readiness` | `core` | `reporting` | `bearer` | verify:read | not required | - | 200:ReadinessReportEnvelope | 400, 401, 403, 404, 409, 422 |
| retentionReport | GET | `/v1/reports/retention` | `experimental` | `reporting` | `bearer` | admin | not required | - | 200:RetentionReportEnvelope | 400, 401, 403, 404, 409, 422 |
| securityReviewPackageReport | GET | `/v1/reports/security-review-package` | `experimental` | `reporting` | `bearer` | package:read | not required | - | 200:SecurityReviewPackageReportEnvelope | 400, 401, 403, 404, 409, 422 |
| securityUpdateEvidenceReport | GET | `/v1/reports/security-update-evidence` | `experimental` | `reporting` | `bearer` | report:read | not required | - | 200:SecurityUpdateEvidenceReportEnvelope | 400, 401, 403, 404, 409, 422 |
| vulnerabilityDecisionSummaryReport | GET | `/v1/reports/vulnerability-decision-summary` | `experimental` | `reporting` | `bearer` | report:read | not required | - | 200:VulnerabilityDecisionSummaryReportEnvelope | 400, 401, 403, 404, 409, 422 |
| vulnerabilityPostureReport | GET | `/v1/reports/vulnerability-posture` | `experimental` | `reporting` | `bearer` | security:read | not required | - | 200:VulnerabilityPostureReportEnvelope | 400, 401, 403, 404, 409, 422 |
| createRetentionOverride | POST | `/v1/retention-overrides` | `experimental` | `governance` | `bearer` | admin | required | CreateRetentionOverrideRequest | 201:RetentionOverrideEnvelope | 400, 401, 403, 404, 409, 422 |
| listRoleBindings | GET | `/v1/role-bindings` | `experimental` | `identity-access` | `bearer` | identity:admin | not required | - | 200:RoleBindingListEnvelope | 400, 401, 403, 404, 409, 422 |
| createRoleBinding | POST | `/v1/role-bindings` | `experimental` | `identity-access` | `bearer` | identity:admin | required | CreateRoleBindingRequest | 201:RoleBindingEnvelope | 400, 401, 403, 404, 409, 422 |
| createSaaSEditionProfile | POST | `/v1/saas/profiles` | `experimental` | `operations-incidents` | `bearer` | instance:admin | required | CreateSaaSEditionProfileRequest | 201:SaaSEditionProfileEnvelope | 400, 401, 403, 404, 409, 422 |
| listSBOMComponents | GET | `/v1/sbom-components` | `core` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:SBOMComponentRecordListEnvelope | 400, 401, 403, 404, 409, 422 |
| createSBOMDiff | POST | `/v1/sbom-diffs` | `experimental` | `release-ledger` | `bearer` | evidence:read | required | CreateSBOMDiffRequest | 201:SBOMDiffEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadSBOM | POST | `/v1/sboms` | `core` | `release-ledger` | `bearer` | evidence:write | required | EvidenceUploadRequest | 201:SBOMEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadSPDXSBOM | POST | `/v1/sboms/spdx` | `core` | `release-ledger` | `bearer` | evidence:write | required | UploadSPDXSBOMRequest | 201:SBOMEnvelope | 400, 401, 403, 404, 409, 422 |
| getSBOM | GET | `/v1/sboms/{id}` | `core` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:SBOMEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadManualSecurityDocument | POST | `/v1/security-documents` | `experimental` | `release-ledger` | `bearer` | security:write | required | UploadManualSecurityDocumentRequest | 201:ManualSecurityDocumentEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadSecurityScan | POST | `/v1/security-scans` | `experimental` | `release-ledger` | `bearer` | security:write | required | UploadSecurityScanRequest | 201:SecurityScanEnvelope | 400, 401, 403, 404, 409, 422 |
| listSigningKeys | GET | `/v1/signing-keys` | `experimental` | `integrity-verification` | `bearer` | verify:read | not required | - | 200:SigningKeyListEnvelope | 400, 401, 403, 404, 409, 422 |
| rotateSigningKey | POST | `/v1/signing-keys/rotate` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | SigningKeyTransitionRequest | 201:SigningKeyEnvelope | 400, 401, 403, 404, 409, 422 |
| revokeSigningKey | POST | `/v1/signing-keys/{id}/revoke` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | SigningKeyTransitionRequest | 200:SigningKeyEnvelope | 400, 401, 403, 404, 409, 422 |
| createSigningOperation | POST | `/v1/signing-operations` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | CreateSigningOperationRequest | 201:SigningOperationEnvelope | 400, 401, 403, 404, 409, 422 |
| createSigningProvider | POST | `/v1/signing-providers` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | CreateSigningProviderRequest | 201:SigningProviderEnvelope | 400, 401, 403, 404, 409, 422 |
| upsertSourceBranch | POST | `/v1/source/branches` | `experimental` | `integration-ingestion` | `bearer` | source:write | required | UpsertSourceBranchRequest | 201:SourceBranchEnvelope | 400, 401, 403, 404, 409, 422 |
| recordSourceCommit | POST | `/v1/source/commits` | `experimental` | `integration-ingestion` | `bearer` | source:write | required | RecordSourceCommitRequest | 201:SourceCommitEnvelope | 400, 401, 403, 404, 409, 422 |
| recordPullRequest | POST | `/v1/source/pull-requests` | `experimental` | `integration-ingestion` | `bearer` | source:write | required | RecordPullRequestRequest | 201:PullRequestEnvelope | 400, 401, 403, 404, 409, 422 |
| listSourceRepositories | GET | `/v1/source/repositories` | `experimental` | `integration-ingestion` | `bearer` | source:read | not required | - | 200:SourceRepositoryListEnvelope | 400, 401, 403, 404, 409, 422 |
| createSourceRepository | POST | `/v1/source/repositories` | `experimental` | `integration-ingestion` | `bearer` | source:write | required | CreateSourceRepositoryRequest | 201:SourceRepositoryEnvelope | 400, 401, 403, 404, 409, 422 |
| linkSSOIdentity | POST | `/v1/sso/identity-links` | `experimental` | `identity-access` | `bearer` | identity:admin | required | LinkSSOIdentityRequest | 201:UserIdentityLinkEnvelope | 400, 401, 403, 404, 409, 422 |
| logoutSSOSession | POST | `/v1/sso/logout` | `supported` | `identity-access` | `bearer` | - | required | EmptyObject | 200:SSOSessionEnvelope | 400, 401, 403, 404, 409, 422 |
| createSSOProvider | POST | `/v1/sso/providers` | `experimental` | `identity-access` | `bearer` | identity:admin | required | CreateSSOProviderRequest | 201:SSOProviderEnvelope | 400, 401, 403, 404, 409, 422 |
| refreshSSOProviderOIDCTrustMaterial | POST | `/v1/sso/providers/{id}/discover-oidc` | `experimental` | `identity-access` | `bearer` | identity:admin | required | EmptyObject | 200:SSOProviderEnvelope | 400, 401, 403, 404, 409, 422 |
| updateSSOProviderTrustMaterial | POST | `/v1/sso/providers/{id}/trust-material` | `experimental` | `identity-access` | `bearer` | identity:admin | required | UpdateSSOProviderTrustMaterialRequest | 200:SSOProviderEnvelope | 400, 401, 403, 404, 409, 422 |
| exchangeSSOCredential | POST | `/v1/sso/session-exchanges` | `supported` | `identity-access` | `sso-credential` | - | not required | ExchangeSSOCredentialRequest | 201:SSOCredentialExchangeEnvelope | 400, 401, 403, 404, 409, 422 |
| createSSOSession | POST | `/v1/sso/sessions` | `experimental` | `identity-access` | `bearer` | identity:admin | required | CreateSSOSessionRequest | 201:SSOSessionCreateEnvelope | 400, 401, 403, 404, 409, 422 |
| revokeSSOSession | POST | `/v1/sso/sessions/{id}/revoke` | `experimental` | `identity-access` | `bearer` | identity:admin | required | EmptyObject | 200:SSOSessionEnvelope | 400, 401, 403, 404, 409, 422 |
| createTransparencyCheckpoint | POST | `/v1/transparency-checkpoints` | `experimental` | `integrity-verification` | `bearer` | keys:admin | required | CreateTransparencyCheckpointRequest | 201:TransparencyCheckpointEnvelope | 400, 401, 403, 404, 409, 422 |
| createUser | POST | `/v1/users` | `experimental` | `identity-access` | `bearer` | identity:admin | required | CreateUserRequest | 201:HumanUserEnvelope | 400, 401, 403, 404, 409, 422 |
| deactivateUser | POST | `/v1/users/{id}/deactivate` | `experimental` | `identity-access` | `bearer` | identity:admin | required | EmptyObject | 200:HumanUserEnvelope | 400, 401, 403, 404, 409, 422 |
| verify | POST | `/v1/verify` | `core` | `integrity-verification` | `bearer` | verify:read | required | VerifySubjectRequest | 200:VerificationResultEnvelope | 400, 401, 403, 404, 409, 422 |
| version | GET | `/v1/version` | `supported` | `platform-operations` | `public` | - | not required | - | 200:VersionInfoEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadVEX | POST | `/v1/vex` | `core` | `release-ledger` | `bearer` | evidence:write | required | EvidenceUploadRequest | 201:VEXDocumentEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadCycloneDXVEX | POST | `/v1/vex/cyclonedx` | `core` | `release-ledger` | `bearer` | evidence:write | required | EvidenceUploadRequest | 201:VEXDocumentEnvelope | 400, 401, 403, 404, 409, 422 |
| previewCycloneDXVEXImport | POST | `/v1/vex/cyclonedx/preview` | `experimental` | `release-ledger` | `bearer` | evidence:read | not required | EvidenceUploadRequest | 200:VEXImportPreviewEnvelope | 400, 401, 403, 404, 409, 422 |
| previewVEXImport | POST | `/v1/vex/preview` | `experimental` | `release-ledger` | `bearer` | evidence:read | not required | EvidenceUploadRequest | 200:VEXImportPreviewEnvelope | 400, 401, 403, 404, 409, 422 |
| getVEX | GET | `/v1/vex/{id}` | `core` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:VEXDocumentEnvelope | 400, 401, 403, 404, 409, 422 |
| getVEXImportReport | GET | `/v1/vex/{id}/import-report` | `experimental` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:VEXImportReportEnvelope | 400, 401, 403, 404, 409, 422 |
| listVulnerabilityDecisions | GET | `/v1/vulnerability-decisions` | `core` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:VulnerabilityDecisionListEnvelope | 400, 401, 403, 404, 409, 422 |
| createVulnerabilityDecision | POST | `/v1/vulnerability-findings/{id}/decisions` | `core` | `release-ledger` | `bearer` | evidence:write | required | CreateVulnerabilityDecisionRequest | 201:VulnerabilityDecisionEnvelope | 400, 401, 403, 404, 409, 422 |
| recordVulnerabilityWorkflow | POST | `/v1/vulnerability-findings/{id}/workflow` | `experimental` | `release-ledger` | `bearer` | security:write | required | RecordVulnerabilityWorkflowRequest | 201:VulnerabilityWorkflowRecordEnvelope | 400, 401, 403, 404, 409, 422 |
| uploadVulnerabilityScan | POST | `/v1/vulnerability-scans` | `core` | `release-ledger` | `bearer` | evidence:write | required | UploadVulnerabilityScanBody | 201:VulnerabilityScanEnvelope | 400, 401, 403, 404, 409, 422 |
| getVulnerabilityScan | GET | `/v1/vulnerability-scans/{id}` | `core` | `release-ledger` | `bearer` | evidence:read | not required | - | 200:VulnerabilityScanEnvelope | 400, 401, 403, 404, 409, 422 |
| createWaiver | POST | `/v1/waivers` | `experimental` | `governance` | `bearer` | policy:write | required | CreateWaiverRequest | 201:WaiverEnvelope | 400, 401, 403, 404, 409, 422 |
| approveWaiver | POST | `/v1/waivers/{id}/approve` | `experimental` | `governance` | `bearer` | policy:write | required | EmptyObject | 200:WaiverEnvelope | 400, 401, 403, 404, 409, 422 |

## Candidate Review Queue

Every `experimental` operation is an explicit candidate for a maintainer decision before a stable API promise: keep isolated as experimental, merge with an adjacent operation, deprecate with a replacement, or remove through the API evolution process. Platform/admin candidates are specifically flagged for internal-exposure review. This is a review queue, not a removal decision.

| Operation | Owner | Candidate action |
| --- | --- | --- |
| instanceAdminSnapshot | `platform-operations` | review internal/admin exposure |
| outboxOperatorDiagnostics | `platform-operations` | review internal/admin exposure |
| replayTerminalOutboxJob | `platform-operations` | review internal/admin exposure |
| readinessDiagnostics | `platform-operations` | review internal/admin exposure |
| uploadAPISecurityScan | `release-ledger` | review experimental scope |
| createArtifactSignature | `integrity-verification` | review experimental scope |
| getArtifactSignature | `integrity-verification` | review experimental scope |
| verifyCosignSignature | `integrity-verification` | review experimental scope |
| verifyAuditChain | `integrity-verification` | review experimental scope |
| listAuditLog | `integrity-verification` | review experimental scope |
| generateBackupManifest | `integrity-verification` | review experimental scope |
| verifyBackupManifest | `integrity-verification` | review experimental scope |
| verifyBuildAttestationSignature | `release-ledger` | review experimental scope |
| listCollectors | `integration-ingestion` | review experimental scope |
| createCollector | `integration-ingestion` | review experimental scope |
| uploadGitHubSourceSnapshot | `integration-ingestion` | review experimental scope |
| uploadGitLabSourceSnapshot | `integration-ingestion` | review experimental scope |
| collectorHealthReport | `integration-ingestion` | review experimental scope |
| recordCollectorRelease | `integration-ingestion` | review experimental scope |
| listCommercialCollectors | `integration-ingestion` | review experimental scope |
| createCommercialCollector | `integration-ingestion` | review experimental scope |
| registerContainerImage | `release-ledger` | review experimental scope |
| listControlEvidence | `governance` | review experimental scope |
| listControlFrameworkTemplatePacks | `governance` | review experimental scope |
| installControlFrameworkTemplatePack | `governance` | review experimental scope |
| listControlFrameworks | `governance` | review experimental scope |
| createControlFramework | `governance` | review experimental scope |
| createSecurityControl | `governance` | review experimental scope |
| getSecurityControl | `governance` | review experimental scope |
| linkControlEvidence | `governance` | review experimental scope |
| createCustomPolicy | `governance` | review experimental scope |
| evaluateCustomPolicy | `governance` | review experimental scope |
| listCustomerPortalAccess | `customer-delivery` | review experimental scope |
| revokeCustomerPortalAccess | `customer-delivery` | review experimental scope |
| customerPortalPackageViewForm | `customer-delivery` | review experimental scope |
| customerPortalPackageView | `customer-delivery` | review experimental scope |
| downloadCustomerPortalPackageView | `customer-delivery` | review experimental scope |
| listDeployments | `operations-incidents` | review experimental scope |
| recordDeployment | `operations-incidents` | review experimental scope |
| getDeployment | `operations-incidents` | review experimental scope |
| createDSSETrustRoot | `integrity-verification` | review experimental scope |
| listDeploymentEnvironments | `operations-incidents` | review experimental scope |
| createDeploymentEnvironment | `operations-incidents` | review experimental scope |
| exportEvidenceBundle | `release-ledger` | review experimental scope |
| importEvidenceBundle | `release-ledger` | review experimental scope |
| createGraphSnapshot | `release-ledger` | review experimental scope |
| createEvidenceSummary | `release-ledger` | review experimental scope |
| searchEvidence | `release-ledger` | review experimental scope |
| listEvidenceLifecycleEvents | `release-ledger` | review experimental scope |
| recordEvidenceLifecycleEvent | `release-ledger` | review experimental scope |
| supersedeEvidence | `release-ledger` | review experimental scope |
| listExceptions | `governance` | review experimental scope |
| receiveIncidentWebhook | `integration-ingestion` | review experimental scope |
| createIncident | `operations-incidents` | review experimental scope |
| recordIncidentTimeline | `operations-incidents` | review experimental scope |
| createIncidentWebhookReceiver | `operations-incidents` | review experimental scope |
| createLegalHold | `governance` | review experimental scope |
| listMarketplaceCollectors | `integration-ingestion` | review experimental scope |
| createMarketplaceCollector | `integration-ingestion` | review experimental scope |
| marketplaceCollectorHealth | `integration-ingestion` | review experimental scope |
| createMerkleBatch | `integrity-verification` | review experimental scope |
| verifyMerkleBatch | `integrity-verification` | review experimental scope |
| createObjectRetentionPolicy | `governance` | review experimental scope |
| verifyObjectRetentionPolicy | `governance` | review experimental scope |
| uploadOpenAPIContract | `release-ledger` | review experimental scope |
| getOpenAPIContract | `release-ledger` | review experimental scope |
| createOpenAPIDiff | `release-ledger` | review experimental scope |
| createOrganization | `identity-access` | review experimental scope |
| evaluatePolicy | `release-ledger` | review experimental scope |
| verifyProviderIdentity | `integrity-verification` | review experimental scope |
| publishPublicTransparencyLogEntry | `integrity-verification` | review experimental scope |
| fetchPublicTransparencyLogEntryProof | `integrity-verification` | review experimental scope |
| verifyPublicTransparencyLogEntry | `integrity-verification` | review experimental scope |
| createPublicTransparencyLog | `integrity-verification` | review experimental scope |
| listQuestionnaireAnswerLibrary | `governance` | review experimental scope |
| createQuestionnaireAnswerLibraryEntry | `governance` | review experimental scope |
| createQuestionnaireDraft | `governance` | review experimental scope |
| createQuestionnairePackage | `governance` | review experimental scope |
| createQuestionnaireTemplate | `governance` | review experimental scope |
| createRedactionProfile | `customer-delivery` | review experimental scope |
| listReleaseCandidates | `release-ledger` | review experimental scope |
| createReleaseCandidate | `release-ledger` | review experimental scope |
| getReleaseCandidate | `release-ledger` | review experimental scope |
| promoteReleaseCandidate | `release-ledger` | review experimental scope |
| rejectReleaseCandidate | `release-ledger` | review experimental scope |
| createRemediationTask | `release-ledger` | review experimental scope |
| createReportTemplate | `reporting` | review merge with report family |
| renderReportTemplate | `reporting` | review merge with report family |
| generateAnomalyReport | `reporting` | review merge with report family |
| controlCoverageReport | `reporting` | review merge with report family |
| craReadinessReport | `reporting` | review merge with report family |
| craReadinessHTMLPackage | `reporting` | review merge with report family |
| craVulnerabilityHandlingReport | `reporting` | review merge with report family |
| signingCustodyReviewReport | `reporting` | review merge with report family |
| incidentReport | `reporting` | review merge with report family |
| missingEvidenceReport | `reporting` | review merge with report family |
| createPDFReportPackage | `reporting` | review merge with report family |
| retentionReport | `reporting` | review merge with report family |
| securityReviewPackageReport | `reporting` | review merge with report family |
| securityUpdateEvidenceReport | `reporting` | review merge with report family |
| vulnerabilityDecisionSummaryReport | `reporting` | review merge with report family |
| vulnerabilityPostureReport | `reporting` | review merge with report family |
| createRetentionOverride | `governance` | review experimental scope |
| listRoleBindings | `identity-access` | review experimental scope |
| createRoleBinding | `identity-access` | review experimental scope |
| createSaaSEditionProfile | `operations-incidents` | review experimental scope |
| createSBOMDiff | `release-ledger` | review experimental scope |
| uploadManualSecurityDocument | `release-ledger` | review experimental scope |
| uploadSecurityScan | `release-ledger` | review experimental scope |
| listSigningKeys | `integrity-verification` | review experimental scope |
| rotateSigningKey | `integrity-verification` | review experimental scope |
| revokeSigningKey | `integrity-verification` | review experimental scope |
| createSigningOperation | `integrity-verification` | review experimental scope |
| createSigningProvider | `integrity-verification` | review experimental scope |
| upsertSourceBranch | `integration-ingestion` | review experimental scope |
| recordSourceCommit | `integration-ingestion` | review experimental scope |
| recordPullRequest | `integration-ingestion` | review experimental scope |
| listSourceRepositories | `integration-ingestion` | review experimental scope |
| createSourceRepository | `integration-ingestion` | review experimental scope |
| linkSSOIdentity | `identity-access` | review experimental scope |
| createSSOProvider | `identity-access` | review experimental scope |
| refreshSSOProviderOIDCTrustMaterial | `identity-access` | review experimental scope |
| updateSSOProviderTrustMaterial | `identity-access` | review experimental scope |
| createSSOSession | `identity-access` | review experimental scope |
| revokeSSOSession | `identity-access` | review experimental scope |
| createTransparencyCheckpoint | `integrity-verification` | review experimental scope |
| createUser | `identity-access` | review experimental scope |
| deactivateUser | `identity-access` | review experimental scope |
| previewCycloneDXVEXImport | `release-ledger` | review experimental scope |
| previewVEXImport | `release-ledger` | review experimental scope |
| getVEXImportReport | `release-ledger` | review experimental scope |
| recordVulnerabilityWorkflow | `release-ledger` | review experimental scope |
| createWaiver | `governance` | review experimental scope |
| approveWaiver | `governance` | review experimental scope |

## Generation And Validation

Run `python3 scripts/api_inventory.py --write` after OpenAPI route metadata changes. Run `make api-inventory-check` in CI; it fails on duplicate operation IDs, missing stability or ownership, broad schemas, and incomplete success, error, or auth contracts.
