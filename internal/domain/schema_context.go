package domain

// This file keeps the legacy transport and persistence model source-compatible
// while schema ownership moves to bounded-context domain packages. New code
// should import the owning context instead of adding constants here.

import (
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	AnomalyReportVersion                                 = experimentaldomain.AnomalyReportVersion
	ApprovalRecordSchemaVersion                          = riskdomain.ApprovalRecordSchemaVersion
	ArtifactSignatureSchemaVersion                       = verificationdomain.ArtifactSignatureSchemaVersion
	AuditChainEntrySchemaVersion                         = verificationdomain.AuditChainEntrySchemaVersion
	BackupManifestSchemaVersion                          = verificationdomain.BackupManifestSchemaVersion
	BuildAttestationSchemaVersion                        = releasedomain.BuildAttestationSchemaVersion
	BuildRunSchemaVersion                                = releasedomain.BuildRunSchemaVersion
	CRAReadinessTemplateVersion                          = packagedomain.CRAReadinessTemplateVersion
	CanonicalizationProfileVersion                       = verificationdomain.CanonicalizationProfileVersion
	CollectorReleaseSchemaVersion                        = integrationdomain.CollectorReleaseSchemaVersion
	CollectorSchemaVersion                               = integrationdomain.CollectorSchemaVersion
	CommercialCollectorVersion                           = integrationdomain.CommercialCollectorVersion
	ContainerImageSchemaVersion                          = releasedomain.ContainerImageSchemaVersion
	ContractDiffSchemaVersion                            = evidencedomain.ContractDiffSchemaVersion
	ControlCoverageTemplateVersion                       = packagedomain.ControlCoverageTemplateVersion
	ControlEvidenceSchemaVersion                         = riskdomain.ControlEvidenceSchemaVersion
	ControlFrameworkSchemaVersion                        = riskdomain.ControlFrameworkSchemaVersion
	CosignVerificationSchemaVersion                      = verificationdomain.CosignVerificationSchemaVersion
	CustomPolicyEvalSchemaVersion                        = riskdomain.CustomPolicyEvalSchemaVersion
	CustomPolicySchemaVersion                            = riskdomain.CustomPolicySchemaVersion
	CustomerPackageSchemaVersion                         = packagedomain.CustomerPackageSchemaVersion
	CustomerPortalAccessVersion                          = packagedomain.CustomerPortalAccessVersion
	DSSETrustRootSchemaVersion                           = verificationdomain.DSSETrustRootSchemaVersion
	DependencyChangeSchemaVersion                        = evidencedomain.DependencyChangeSchemaVersion
	DeploymentEnvironmentVersion                         = operationsdomain.DeploymentEnvironmentVersion
	DeploymentEventSchemaVersion                         = operationsdomain.DeploymentEventSchemaVersion
	EvidenceBundleImportVersion                          = packagedomain.EvidenceBundleImportVersion
	EvidenceBundleSchemaVersion                          = packagedomain.EvidenceBundleSchemaVersion
	EvidenceGraphSnapshotVersion                         = packagedomain.EvidenceGraphSnapshotVersion
	EvidenceItemSchemaVersion                            = evidencedomain.EvidenceItemSchemaVersion
	EvidenceLifecycleSchemaVersion                       = evidencedomain.EvidenceLifecycleSchemaVersion
	EvidenceSummaryVersion                               = packagedomain.EvidenceSummaryVersion
	HumanUserSchemaVersion                               = identitydomain.HumanUserSchemaVersion
	IncidentSchemaVersion                                = operationsdomain.IncidentSchemaVersion
	IncidentTimelineSchemaVersion                        = operationsdomain.IncidentTimelineSchemaVersion
	IncidentWebhookEventVersion                          = operationsdomain.IncidentWebhookEventVersion
	IncidentWebhookReceiverVersion                       = operationsdomain.IncidentWebhookReceiverVersion
	LegalHoldSchemaVersion                               = operationsdomain.LegalHoldSchemaVersion
	ManualSecurityDocSchemaVersion                       = evidencedomain.ManualSecurityDocSchemaVersion
	MarketplaceCollectorVersion                          = experimentaldomain.MarketplaceCollectorVersion
	MerkleBatchSchemaVersion                             = verificationdomain.MerkleBatchSchemaVersion
	ObjectRetentionPolicyVersion                         = verificationdomain.ObjectRetentionPolicyVersion
	OrganizationSchemaVersion                            = identitydomain.OrganizationSchemaVersion
	PDFReportPackageVersion                              = packagedomain.PDFReportPackageVersion
	PolicySetVersion                                     = riskdomain.PolicySetVersion
	ProviderVerificationVersion                          = identitydomain.ProviderVerificationVersion
	PublicTransparencyEntryVersion                       = experimentaldomain.PublicTransparencyEntryVersion
	PublicTransparencyLogVersion                         = experimentaldomain.PublicTransparencyLogVersion
	PullRequestSchemaVersion                             = integrationdomain.PullRequestSchemaVersion
	QuestionnaireAnswerLibraryVersion                    = packagedomain.QuestionnaireAnswerLibraryVersion
	QuestionnaireDraftVersion                            = packagedomain.QuestionnaireDraftVersion
	QuestionnairePackageVersion                          = packagedomain.QuestionnairePackageVersion
	QuestionnaireTemplateVersion                         = packagedomain.QuestionnaireTemplateVersion
	RedactionProfileSchemaVersion                        = packagedomain.RedactionProfileSchemaVersion
	ReleaseBundleSchemaVersion                           = packagedomain.ReleaseBundleSchemaVersion
	ReleaseCandidateSchemaVersion                        = releasedomain.ReleaseCandidateSchemaVersion
	ReleaseEvidenceFlowVersion                           = releasedomain.ReleaseEvidenceFlowVersion
	ReleaseReadinessTemplateVersion                      = packagedomain.ReleaseReadinessTemplateVersion
	ReleaseSecuritySummaryVersion                        = riskdomain.ReleaseSecuritySummaryVersion
	RemediationTaskSchemaVersion                         = operationsdomain.RemediationTaskSchemaVersion
	ReportTemplateSchemaVersion                          = packagedomain.ReportTemplateSchemaVersion
	RetentionOverrideSchemaVersion                       = operationsdomain.RetentionOverrideSchemaVersion
	RoleBindingSchemaVersion                             = identitydomain.RoleBindingSchemaVersion
	SBOMDiffSchemaVersion                                = evidencedomain.SBOMDiffSchemaVersion
	SSOProviderSchemaVersion                             = identitydomain.SSOProviderSchemaVersion
	SSOSessionSchemaVersion                              = identitydomain.SSOSessionSchemaVersion
	SaaSEditionProfileVersion                            = experimentaldomain.SaaSEditionProfileVersion
	SecurityControlSchemaVersion                         = riskdomain.SecurityControlSchemaVersion
	SecurityScanSchemaVersion                            = evidencedomain.SecurityScanSchemaVersion
	SigningKeyDefaultProvider                            = verificationdomain.SigningKeyDefaultProvider
	SigningKeyHistoricalValidityCompromised              = verificationdomain.SigningKeyHistoricalValidityCompromised
	SigningKeyHistoricalValidityInvalidateAll            = verificationdomain.SigningKeyHistoricalValidityInvalidateAll
	SigningKeyHistoricalValidityInvalidateFromCompromise = verificationdomain.SigningKeyHistoricalValidityInvalidateFromCompromise
	SigningKeyHistoricalValidityOutsideWindow            = verificationdomain.SigningKeyHistoricalValidityOutsideWindow
	SigningKeyHistoricalValidityPreserve                 = verificationdomain.SigningKeyHistoricalValidityPreserve
	SigningKeyHistoricalValidityValid                    = verificationdomain.SigningKeyHistoricalValidityValid
	SigningKeyRevocationCompromised                      = verificationdomain.SigningKeyRevocationCompromised
	SigningKeyRevocationOrdinary                         = verificationdomain.SigningKeyRevocationOrdinary
	SigningKeyStatusActive                               = verificationdomain.SigningKeyStatusActive
	SigningKeyStatusRetiring                             = verificationdomain.SigningKeyStatusRetiring
	SigningKeyStatusRevoked                              = verificationdomain.SigningKeyStatusRevoked
	SigningOperationVersion                              = verificationdomain.SigningOperationVersion
	SigningProviderSchemaVersion                         = verificationdomain.SigningProviderSchemaVersion
	SourceBranchSchemaVersion                            = integrationdomain.SourceBranchSchemaVersion
	SourceCommitSchemaVersion                            = integrationdomain.SourceCommitSchemaVersion
	SourceRepositorySchemaVersion                        = integrationdomain.SourceRepositorySchemaVersion
	TransparencyCheckpointVersion                        = verificationdomain.TransparencyCheckpointVersion
	VEXDocumentSchemaVersion                             = evidencedomain.VEXDocumentSchemaVersion
	VEXImportPreviewSchemaVersion                        = evidencedomain.VEXImportPreviewSchemaVersion
	VEXImportReportSchemaVersion                         = evidencedomain.VEXImportReportSchemaVersion
	VerificationProfileArtifactSignatureMetadata         = verificationdomain.VerificationProfileArtifactSignatureMetadata
	VerificationProfileAuditChainIntegrity               = verificationdomain.VerificationProfileAuditChainIntegrity
	VerificationProfileAuditChainMerkleCheckpoint        = verificationdomain.VerificationProfileAuditChainMerkleCheckpoint
	VerificationProfileAuditChainReleaseManifest         = verificationdomain.VerificationProfileAuditChainReleaseManifest
	VerificationProfileBackupManifest                    = verificationdomain.VerificationProfileBackupManifest
	VerificationProfileCosignFull                        = verificationdomain.VerificationProfileCosignFull
	VerificationProfileCustomerPackageManifest           = verificationdomain.VerificationProfileCustomerPackageManifest
	VerificationProfileDSSEAttestationSignature          = verificationdomain.VerificationProfileDSSEAttestationSignature
	VerificationProfileEvidenceCanonicalHash             = verificationdomain.VerificationProfileEvidenceCanonicalHash
	VerificationProfileMerkleCheckpoint                  = verificationdomain.VerificationProfileMerkleCheckpoint
	VerificationProfileObjectRetention                   = verificationdomain.VerificationProfileObjectRetention
	VerificationProfileReleaseArtifactManifest           = verificationdomain.VerificationProfileReleaseArtifactManifest
	VerificationProfileReleaseBundleSignature            = verificationdomain.VerificationProfileReleaseBundleSignature
	VerificationProfileSchemaVersion                     = verificationdomain.VerificationProfileSchemaVersion
	VerificationProfileTransparencyInclusion             = verificationdomain.VerificationProfileTransparencyInclusion
	VerificationResultSchemaVersion                      = verificationdomain.VerificationResultSchemaVersion
	VerificationStateError                               = verificationdomain.VerificationStateError
	VerificationStateFailed                              = verificationdomain.VerificationStateFailed
	VerificationStateLimited                             = verificationdomain.VerificationStateLimited
	VerificationStateNotVerified                         = verificationdomain.VerificationStateNotVerified
	VerificationStatePassed                              = verificationdomain.VerificationStatePassed
	VerificationStateSkipped                             = verificationdomain.VerificationStateSkipped
	VulnerabilityDecisionVersion                         = riskdomain.VulnerabilityDecisionVersion
	WaiverSchemaVersion                                  = riskdomain.WaiverSchemaVersion
)
