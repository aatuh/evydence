# API Contract Matrix

This generated reference inventories Evydence `/v1` route contract precision from `openapi.yaml`.
It is a planning aid for production contract hardening; `broad` means the route still uses a shared envelope, unspecified body, or generic schema where an endpoint-specific contract should be considered.

Generated from 160 operations: 61 precise, 99 broad.

| Method | Path | Operation | Auth | Scopes | Idempotency | Params | Request | 2xx Response | Precision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GET | /v1/admin/instance | instanceAdminSnapshot | Bearer | instance:admin | - | - | - | 200:application/json:InstanceAdminSnapshotEnvelope | precise |
| GET | /v1/api-keys | listAPIKeys | Bearer | admin | - | - | - | 200:application/json:APIKeyListEnvelope | precise |
| POST | /v1/api-keys | createAPIKey | Bearer | admin | required | - | application/json:CreateAPIKeyRequest | 201:application/json:APIKeyCreateEnvelope | precise |
| POST | /v1/api-security-scans | uploadAPISecurityScan | Bearer | security:write | required | - | - | 201:unspecified | broad |
| POST | /v1/approvals | createApproval | Bearer | release:write | required | - | - | 201:unspecified | broad |
| POST | /v1/artifact-signatures | createArtifactSignature | Bearer | evidence:write | required | - | - | 201:unspecified | broad |
| GET | /v1/artifact-signatures/{id} | getArtifactSignature | Bearer | evidence:read | - | - | - | 200:unspecified | broad |
| POST | /v1/artifact-signatures/{id}/verify-cosign | verifyCosignSignature | Bearer | verify:read | required | - | - | 200:unspecified | broad |
| POST | /v1/artifacts | registerArtifact | Bearer | evidence:write | required | - | application/json:RegisterArtifactRequest | 201:application/json:ArtifactEnvelope | precise |
| GET | /v1/audit-chain/verify | verifyAuditChain | Bearer | verify:read | - | - | - | 200:application/json:VerificationResultEnvelope | precise |
| GET | /v1/audit-log | listAuditLog | Bearer | admin | - | query:limit, query:since, query:subject_id, query:subject_type | - | 200:application/json:AuditChainEntryListEnvelope | precise |
| POST | /v1/backup-manifests | generateBackupManifest | Bearer | admin | required | - | application/json:EmptyObject | 201:application/json:BackupManifestEnvelope | precise |
| GET | /v1/backup-manifests/{id}/verify | verifyBackupManifest | Bearer | verify:read | - | path:id | - | 200:application/json:VerificationResultEnvelope | precise |
| POST | /v1/build-attestations/{id}/verify-signature | verifyBuildAttestationSignature | Bearer | verify:read | required | - | - | 200:unspecified | broad |
| POST | /v1/builds | createBuild | Bearer | build:write | required | - | application/json:CreateBuildRequest | 201:application/json:BuildRunEnvelope | precise |
| GET | /v1/builds/{id} | getBuild | Bearer | build:read | - | path:id | - | 200:application/json:BuildRunEnvelope | precise |
| POST | /v1/builds/{id}/attestations | uploadBuildAttestation | Bearer | build:write | required | - | - | 201:unspecified | broad |
| GET | /v1/collectors | listCollectors | Bearer | collector:read | - | - | - | 200:application/json:CollectorListEnvelope | precise |
| POST | /v1/collectors | createCollector | Bearer | collector:admin | required | - | application/json:CreateCollectorRequest | 201:application/json:CollectorCreateEnvelope | precise |
| POST | /v1/collectors/github/source-snapshots | uploadGitHubSourceSnapshot | Bearer | source:write | required | - | application/json:SourceSnapshotRequest | 201:application/json:SourceSnapshotEnvelope | precise |
| POST | /v1/collectors/gitlab/source-snapshots | uploadGitLabSourceSnapshot | Bearer | source:write | required | - | application/json:SourceSnapshotRequest | 201:application/json:SourceSnapshotEnvelope | precise |
| GET | /v1/collectors/{id}/health | collectorHealthReport | Bearer | collector:read | - | - | - | 200:unspecified | broad |
| POST | /v1/collectors/{id}/releases | recordCollectorRelease | Bearer | collector:admin | required | - | - | 201:unspecified | broad |
| GET | /v1/commercial-collectors | listCommercialCollectors | Bearer | collector:read | - | - | - | 200:unspecified | broad |
| POST | /v1/commercial-collectors | createCommercialCollector | Bearer | collector:admin | required | - | - | 201:unspecified | broad |
| POST | /v1/container-images | registerContainerImage | Bearer | evidence:write | required | - | - | 201:unspecified | broad |
| GET | /v1/control-evidence | listControlEvidence | Bearer | controls:read | - | query:control_id, query:product_id, query:release_id | - | 200:application/json:ControlEvidenceListEnvelope | precise |
| GET | /v1/control-framework-template-packs | listControlFrameworkTemplatePacks | Bearer | controls:read | - | - | - | 200:unspecified | broad |
| POST | /v1/control-framework-template-packs/{slug}/install | installControlFrameworkTemplatePack | Bearer | controls:admin | required | - | - | 201:unspecified | broad |
| GET | /v1/control-frameworks | listControlFrameworks | Bearer | controls:read | - | - | - | 200:application/json:ControlFrameworkListEnvelope | precise |
| POST | /v1/control-frameworks | createControlFramework | Bearer | controls:admin | required | - | application/json:CreateControlFrameworkRequest | 201:application/json:ControlFrameworkEnvelope | precise |
| POST | /v1/controls | createSecurityControl | Bearer | controls:admin | required | - | application/json:CreateSecurityControlRequest | 201:application/json:SecurityControlEnvelope | precise |
| GET | /v1/controls/{id} | getSecurityControl | Bearer | controls:read | - | path:id | - | 200:application/json:SecurityControlEnvelope | precise |
| POST | /v1/controls/{id}/evidence | linkControlEvidence | Bearer | controls:write | required | path:id | application/json:LinkControlEvidenceRequest | 201:application/json:ControlEvidenceEnvelope | precise |
| POST | /v1/custom-policies | createCustomPolicy | Bearer | policy:write | required | - | - | 201:unspecified | broad |
| POST | /v1/custom-policies/{id}/evaluate | evaluateCustomPolicy | Bearer | policy:read | required | - | - | 201:unspecified | broad |
| POST | /v1/customer-packages | createCustomerPackage | Bearer | package:write | required | - | - | 201:unspecified | broad |
| GET | /v1/customer-packages/{id} | getCustomerPackage | Bearer | package:read | - | - | - | 200:unspecified | broad |
| GET | /v1/customer-packages/{id}/download | downloadCustomerPackage | Bearer | package:read | - | path:id | - | 200:application/zip:string/binary | precise |
| POST | /v1/customer-portal/access | createCustomerPortalAccess | Bearer | package:write | required | - | application/json:CreateCustomerPortalAccessRequest | 201:application/json:CustomerPortalAccessCreateEnvelope | precise |
| POST | /v1/customer-portal/package | accessCustomerPortalPackage | public | - | not required | - | application/json:CustomerPortalPackageRequest | 200:application/json:DataEnvelope | broad |
| POST | /v1/customer-portal/package/download | downloadCustomerPortalPackage | public | - | not required | - | application/json:CustomerPortalPackageRequest | 200:application/zip:string/binary | precise |
| GET | /v1/deployments | listDeployments | Bearer | deployment:read | - | - | - | 200:unspecified | broad |
| POST | /v1/deployments | recordDeployment | Bearer | deployment:write | required | - | - | 201:unspecified | broad |
| GET | /v1/deployments/{id} | getDeployment | Bearer | deployment:read | - | - | - | 200:unspecified | broad |
| POST | /v1/dsse-trust-roots | createDSSETrustRoot | Bearer | keys:admin | required | - | - | 201:unspecified | broad |
| GET | /v1/environments | listDeploymentEnvironments | Bearer | deployment:read | - | - | - | 200:unspecified | broad |
| POST | /v1/environments | createDeploymentEnvironment | Bearer | deployment:write | required | - | - | 201:unspecified | broad |
| GET | /v1/evidence | listEvidence | Bearer | evidence:read | - | query:release_id, query:type | - | 200:application/json:EvidenceItemListEnvelope | precise |
| POST | /v1/evidence | createEvidence | Bearer | evidence:write | required | - | application/json:CreateEvidenceRequest | 201:application/json:EvidenceItemEnvelope | precise |
| POST | /v1/evidence-bundles | exportEvidenceBundle | Bearer | bundle:read | required | - | - | 201:unspecified | broad |
| POST | /v1/evidence-bundles/import | importEvidenceBundle | Bearer | bundle:write | required | - | - | 201:unspecified | broad |
| POST | /v1/evidence-graph-snapshots | createGraphSnapshot | Bearer | evidence:read | required | - | application/json:CreateGraphSnapshotRequest | 201:application/json:EvidenceGraphSnapshotEnvelope | precise |
| POST | /v1/evidence-summaries | createEvidenceSummary | Bearer | report:read | required | - | - | 201:unspecified | broad |
| GET | /v1/evidence/search | searchEvidence | Bearer | evidence:read | - | query:cursor, query:limit, query:product_id, query:project_id, query:release_id, query:source, query:tag, query:type | - | 200:application/json:EvidenceSearchEnvelope | precise |
| GET | /v1/evidence/{id} | getEvidence | Bearer | evidence:read | - | path:id | - | 200:application/json:EvidenceItemEnvelope | precise |
| GET | /v1/evidence/{id}/lifecycle-events | listEvidenceLifecycleEvents | Bearer | evidence:read | - | - | - | 200:unspecified | broad |
| POST | /v1/evidence/{id}/lifecycle-events | recordEvidenceLifecycleEvent | Bearer | evidence:write | required | - | - | 201:unspecified | broad |
| POST | /v1/evidence/{id}/link | linkEvidence | Bearer | evidence:write | required | - | - | 201:unspecified | broad |
| POST | /v1/evidence/{id}/supersede | supersedeEvidence | Bearer | evidence:write | required | - | - | 201:unspecified | broad |
| GET | /v1/exceptions | listExceptions | Bearer | verify:read | - | - | - | 200:unspecified | broad |
| POST | /v1/exceptions | createException | Bearer | release:write | required | - | - | 201:unspecified | broad |
| POST | /v1/exceptions/{id}/approve | approveException | Bearer | release:write | required | - | - | 200:unspecified | broad |
| GET | /v1/health | health | public | - | - | - | - | 200:application/json:HealthStatusEnvelope | precise |
| POST | /v1/incident-webhooks/{receiver_id} | receiveIncidentWebhook | public | - | not required | header:X-Evydence-Webhook-Event-ID, header:X-Evydence-Webhook-Signature, header:X-Evydence-Webhook-Timestamp, path:receiver_id | application/json:DataEnvelope | 201:application/json:DataEnvelope | broad |
| POST | /v1/incidents | createIncident | Bearer | incident:write | required | - | - | 201:unspecified | broad |
| POST | /v1/incidents/{id}/timeline | recordIncidentTimeline | Bearer | incident:write | required | - | - | 201:unspecified | broad |
| POST | /v1/incidents/{id}/webhook-receivers | createIncidentWebhookReceiver | Bearer | incident:write | required | path:id | application/json:DataEnvelope | 201:application/json:DataEnvelope | broad |
| POST | /v1/legal-holds | createLegalHold | Bearer | admin | required | - | - | 201:unspecified | broad |
| GET | /v1/marketplace-collectors | listMarketplaceCollectors | Bearer | collector:read | - | - | - | 200:unspecified | broad |
| POST | /v1/marketplace-collectors | createMarketplaceCollector | Bearer | collector:admin | required | - | - | 201:unspecified | broad |
| GET | /v1/marketplace-collectors/{id}/health | marketplaceCollectorHealth | Bearer | collector:read | - | - | - | 200:unspecified | broad |
| POST | /v1/merkle-batches | createMerkleBatch | Bearer | keys:admin | required | - | - | 201:unspecified | broad |
| GET | /v1/merkle-batches/{id}/verify | verifyMerkleBatch | Bearer | verify:read | - | - | - | 200:unspecified | broad |
| GET | /v1/metrics | metrics | Bearer | admin | - | - | - | 200:application/json:MetricsSnapshotEnvelope,text/plain:string | precise |
| POST | /v1/object-retention-policies | createObjectRetentionPolicy | Bearer | admin | required | - | - | 201:unspecified | broad |
| POST | /v1/object-retention-policies/{id}/verify | verifyObjectRetentionPolicy | Bearer | verify:read | required | - | - | 200:unspecified | broad |
| POST | /v1/openapi-contracts | uploadOpenAPIContract | Bearer | evidence:write | required | - | - | 201:unspecified | broad |
| GET | /v1/openapi-contracts/{id} | getOpenAPIContract | Bearer | evidence:read | - | - | - | 200:unspecified | broad |
| POST | /v1/openapi-diffs | createOpenAPIDiff | Bearer | evidence:read | required | - | - | 201:unspecified | broad |
| GET | /v1/openapi.json | openapi | public | - | - | - | - | 200:application/json:OpenAPIDocument | precise |
| POST | /v1/organizations | createOrganization | Bearer | identity:admin | required | - | application/json:CreateOrganizationRequest | 201:application/json:OrganizationEnvelope | precise |
| POST | /v1/policies/evaluate | evaluatePolicy | Bearer | verify:read | required | - | - | 201:unspecified | broad |
| GET | /v1/products | listProducts | Bearer | product:read | - | - | - | 200:application/json:ProductListEnvelope | precise |
| POST | /v1/products | createProduct | Bearer | product:write | required | - | application/json:CreateProductRequest | 201:application/json:ProductEnvelope | precise |
| POST | /v1/projects | createProject | Bearer | project:write | required | - | application/json:CreateProjectRequest | 201:application/json:ProjectEnvelope | precise |
| POST | /v1/provider-verifications | verifyProviderIdentity | Bearer | identity:admin | required | - | application/json:VerifyProviderIdentityRequest | 201:application/json:ProviderVerificationEnvelope | precise |
| POST | /v1/public-transparency-log-entries | publishPublicTransparencyLogEntry | Bearer | keys:admin | required | - | - | 201:unspecified | broad |
| POST | /v1/public-transparency-logs | createPublicTransparencyLog | Bearer | keys:admin | required | - | - | 201:unspecified | broad |
| POST | /v1/questionnaire-drafts | createQuestionnaireDraft | Bearer | package:read | required | - | - | 201:unspecified | broad |
| POST | /v1/questionnaire-packages | createQuestionnairePackage | Bearer | package:write | required | - | - | 201:unspecified | broad |
| POST | /v1/questionnaire-templates | createQuestionnaireTemplate | Bearer | package:write | required | - | - | 201:unspecified | broad |
| GET | /v1/ready | ready | public | - | - | - | - | 200:application/json:ReadinessStatusEnvelope | precise |
| POST | /v1/redaction-profiles | createRedactionProfile | Bearer | package:write | required | - | - | 201:unspecified | broad |
| POST | /v1/release-bundles | createReleaseBundle | Bearer | bundle:write | required | - | application/json:CreateReleaseBundleRequest | 201:application/json:DataEnvelope | broad |
| GET | /v1/release-bundles/{id} | getReleaseBundle | Bearer | bundle:read | - | - | - | 200:unspecified | broad |
| GET | /v1/release-bundles/{id}/manifest | getReleaseBundleManifest | Bearer | bundle:read | - | - | - | 200:unspecified | broad |
| GET | /v1/release-bundles/{id}/verify | verifyReleaseBundle | Bearer | verify:read | - | path:id | - | 200:application/json:ReleaseBundleVerificationEnvelope | precise |
| GET | /v1/release-candidates | listReleaseCandidates | Bearer | release:read | - | - | - | 200:unspecified | broad |
| POST | /v1/release-candidates | createReleaseCandidate | Bearer | release:write | required | - | - | 201:unspecified | broad |
| GET | /v1/release-candidates/{id} | getReleaseCandidate | Bearer | release:read | - | - | - | 200:unspecified | broad |
| POST | /v1/release-candidates/{id}/promote | promoteReleaseCandidate | Bearer | release:write | required | - | - | 200:unspecified | broad |
| POST | /v1/release-candidates/{id}/reject | rejectReleaseCandidate | Bearer | release:write | required | - | - | 200:unspecified | broad |
| POST | /v1/releases | createRelease | Bearer | release:write | required | - | application/json:CreateReleaseRequest | 201:application/json:ReleaseEnvelope | precise |
| GET | /v1/releases/{id} | getRelease | Bearer | release:read | - | path:id | - | 200:application/json:ReleaseEnvelope | precise |
| POST | /v1/releases/{id}/approve | approveRelease | Bearer | release:write | required | path:id | application/json:EmptyObject | 200:application/json:ReleaseEnvelope | precise |
| POST | /v1/releases/{id}/freeze | freezeRelease | Bearer | release:write | required | path:id | application/json:EmptyObject | 200:application/json:ReleaseEnvelope | precise |
| POST | /v1/remediation-tasks | createRemediationTask | Bearer | incident:write | required | - | - | 201:unspecified | broad |
| POST | /v1/report-templates | createReportTemplate | Bearer | report:read | required | - | - | 201:unspecified | broad |
| POST | /v1/report-templates/{id}/render | renderReportTemplate | Bearer | report:read | required | - | - | 201:unspecified | broad |
| POST | /v1/reports/anomaly | generateAnomalyReport | Bearer | report:read | required | - | - | 201:unspecified | broad |
| GET | /v1/reports/control-coverage | controlCoverageReport | Bearer | report:read | - | query:framework_id, query:product_id, query:release_id | - | 200:application/json:ReadinessReportEnvelope | precise |
| GET | /v1/reports/cra-readiness | craReadinessReport | Bearer | report:read | - | query:product_id, query:release_id | - | 200:application/json:ReadinessReportEnvelope | precise |
| GET | /v1/reports/cra-readiness-html | craReadinessHTMLPackage | Bearer | report:read | - | - | - | 200:unspecified | broad |
| GET | /v1/reports/incident-package | incidentReport | Bearer | incident:read | - | - | - | 200:unspecified | broad |
| GET | /v1/reports/missing-evidence | missingEvidenceReport | Bearer | verify:read | - | - | - | 200:unspecified | broad |
| POST | /v1/reports/pdf | createPDFReportPackage | Bearer | report:read | required | - | - | 201:unspecified | broad |
| GET | /v1/reports/release-readiness | releaseReadinessReport | Bearer | verify:read | - | query:release_id | - | 200:application/json:ReadinessReportEnvelope | precise |
| GET | /v1/reports/retention | retentionReport | Bearer | admin | - | - | - | 200:unspecified | broad |
| GET | /v1/reports/security-review-package | securityReviewPackageReport | Bearer | package:read | - | - | - | 200:unspecified | broad |
| GET | /v1/reports/vulnerability-posture | vulnerabilityPostureReport | Bearer | security:read | - | - | - | 200:unspecified | broad |
| POST | /v1/retention-overrides | createRetentionOverride | Bearer | admin | required | - | - | 201:unspecified | broad |
| GET | /v1/role-bindings | listRoleBindings | Bearer | identity:admin | - | - | - | 200:application/json:RoleBindingListEnvelope | precise |
| POST | /v1/role-bindings | createRoleBinding | Bearer | identity:admin | required | - | application/json:CreateRoleBindingRequest | 201:application/json:RoleBindingEnvelope | precise |
| POST | /v1/saas/profiles | createSaaSEditionProfile | Bearer | instance:admin | required | - | - | 201:unspecified | broad |
| GET | /v1/sbom-components | listSBOMComponents | Bearer | evidence:read | - | query:artifact_id, query:limit, query:purl, query:query, query:release_id, query:sbom_id | - | 200:application/json:DataEnvelope | broad |
| POST | /v1/sbom-diffs | createSBOMDiff | Bearer | evidence:read | required | - | - | 201:unspecified | broad |
| POST | /v1/sboms | uploadSBOM | Bearer | evidence:write | required | - | application/json:EvidenceUploadRequest | 201:application/json:SBOMEnvelope | precise |
| POST | /v1/sboms/spdx | uploadSPDXSBOM | Bearer | evidence:write | required | - | - | 201:unspecified | broad |
| GET | /v1/sboms/{id} | getSBOM | Bearer | evidence:read | - | path:id | - | 200:application/json:SBOMEnvelope | precise |
| POST | /v1/security-documents | uploadManualSecurityDocument | Bearer | security:write | required | - | - | 201:unspecified | broad |
| POST | /v1/security-scans | uploadSecurityScan | Bearer | security:write | required | - | - | 201:unspecified | broad |
| GET | /v1/signing-keys | listSigningKeys | Bearer | verify:read | - | - | - | 200:unspecified | broad |
| POST | /v1/signing-keys/rotate | rotateSigningKey | Bearer | keys:admin | required | - | - | 201:unspecified | broad |
| POST | /v1/signing-keys/{id}/revoke | revokeSigningKey | Bearer | keys:admin | required | - | - | 200:unspecified | broad |
| POST | /v1/signing-operations | createSigningOperation | Bearer | keys:admin | required | - | - | 201:unspecified | broad |
| POST | /v1/signing-providers | createSigningProvider | Bearer | keys:admin | required | - | - | 201:unspecified | broad |
| POST | /v1/source/branches | upsertSourceBranch | Bearer | source:write | required | - | - | 201:unspecified | broad |
| POST | /v1/source/commits | recordSourceCommit | Bearer | source:write | required | - | - | 201:unspecified | broad |
| POST | /v1/source/pull-requests | recordPullRequest | Bearer | source:write | required | - | - | 201:unspecified | broad |
| GET | /v1/source/repositories | listSourceRepositories | Bearer | source:read | - | - | - | 200:unspecified | broad |
| POST | /v1/source/repositories | createSourceRepository | Bearer | source:write | required | - | - | 201:unspecified | broad |
| POST | /v1/sso/identity-links | linkSSOIdentity | Bearer | identity:admin | required | - | application/json:LinkSSOIdentityRequest | 201:application/json:UserIdentityLinkEnvelope | precise |
| POST | /v1/sso/providers | createSSOProvider | Bearer | identity:admin | required | - | application/json:CreateSSOProviderRequest | 201:application/json:SSOProviderEnvelope | precise |
| POST | /v1/sso/sessions | createSSOSession | Bearer | identity:admin | required | - | application/json:CreateSSOSessionRequest | 201:application/json:SSOSessionCreateEnvelope | precise |
| POST | /v1/sso/sessions/{id}/revoke | revokeSSOSession | Bearer | identity:admin | required | path:id | application/json:EmptyObject | 200:application/json:SSOSessionEnvelope | precise |
| POST | /v1/transparency-checkpoints | createTransparencyCheckpoint | Bearer | keys:admin | required | - | - | 201:unspecified | broad |
| POST | /v1/users | createUser | Bearer | identity:admin | required | - | application/json:CreateUserRequest | 201:application/json:HumanUserEnvelope | precise |
| POST | /v1/users/{id}/deactivate | deactivateUser | Bearer | identity:admin | required | path:id | application/json:EmptyObject | 200:application/json:HumanUserEnvelope | precise |
| POST | /v1/verify | verify | Bearer | verify:read | required | - | - | 200:unspecified | broad |
| GET | /v1/version | version | public | - | - | - | - | 200:application/json:VersionInfoEnvelope | precise |
| POST | /v1/vex | uploadVEX | Bearer | evidence:write | required | - | application/json:EvidenceUploadRequest | 201:application/json:VEXDocumentEnvelope | precise |
| POST | /v1/vex/cyclonedx | uploadCycloneDXVEX | Bearer | evidence:write | required | - | application/json:EvidenceUploadRequest | 201:application/json:VEXDocumentEnvelope | precise |
| GET | /v1/vex/{id} | getVEX | Bearer | evidence:read | - | path:id | - | 200:application/json:VEXDocumentEnvelope | precise |
| POST | /v1/vulnerability-findings/{id}/decisions | createVulnerabilityDecision | Bearer | evidence:write | required | - | - | 201:unspecified | broad |
| POST | /v1/vulnerability-findings/{id}/workflow | recordVulnerabilityWorkflow | Bearer | security:write | required | - | - | 201:unspecified | broad |
| POST | /v1/vulnerability-scans | uploadVulnerabilityScan | Bearer | evidence:write | required | - | application/json:UploadVulnerabilityScanRequest | 201:application/json:VulnerabilityScanEnvelope | precise |
| GET | /v1/vulnerability-scans/{id} | getVulnerabilityScan | Bearer | evidence:read | - | path:id | - | 200:application/json:VulnerabilityScanEnvelope | precise |
| POST | /v1/waivers | createWaiver | Bearer | policy:write | required | - | - | 201:unspecified | broad |
| POST | /v1/waivers/{id}/approve | approveWaiver | Bearer | policy:write | required | - | - | 200:unspecified | broad |

