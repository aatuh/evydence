package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// EnsureOutboxDeduplicationKey derives a stable key for one logical worker
// operation. The random job id and creation time are deliberately excluded so
// retried command paths resolve to the same durable job instead of producing
// duplicate worker effects.
func EnsureOutboxDeduplicationKey(job *OutboxJob) error {
	if job == nil {
		return ErrValidation
	}
	if strings.TrimSpace(job.DeduplicationKey) != "" {
		job.DeduplicationKey = strings.TrimSpace(job.DeduplicationKey)
		return nil
	}
	canonical, err := json.Marshal(struct {
		TenantID    string         `json:"tenant_id"`
		Kind        string         `json:"kind"`
		SubjectType string         `json:"subject_type"`
		SubjectID   string         `json:"subject_id"`
		Payload     map[string]any `json:"payload"`
	}{
		TenantID: strings.TrimSpace(job.TenantID), Kind: strings.TrimSpace(job.Kind),
		SubjectType: strings.TrimSpace(job.SubjectType), SubjectID: strings.TrimSpace(job.SubjectID), Payload: job.Payload,
	})
	if err != nil {
		return ErrValidation
	}
	digest := sha256.Sum256(canonical)
	job.DeduplicationKey = "outbox:" + hex.EncodeToString(digest[:])
	return nil
}

func cloneState(state PersistedState) (PersistedState, error) {
	body, err := json.Marshal(state)
	if err != nil {
		return PersistedState{}, err
	}
	var out PersistedState
	if err := json.Unmarshal(body, &out); err != nil {
		return PersistedState{}, err
	}
	return normalizeState(out), nil
}

func cloneAuditChain(chain map[string][]domain.AuditChainEntry) (map[string][]domain.AuditChainEntry, error) {
	cloned, err := cloneState(PersistedState{Chain: chain})
	if err != nil {
		return nil, err
	}
	return cloned.Chain, nil
}

func normalizeState(state PersistedState) PersistedState {
	if state.Tenants == nil {
		state.Tenants = map[string]domain.Tenant{}
	}
	if state.Organizations == nil {
		state.Organizations = map[string]domain.Organization{}
	}
	if state.Users == nil {
		state.Users = map[string]domain.HumanUser{}
	}
	if state.RoleBindings == nil {
		state.RoleBindings = map[string]domain.RoleBinding{}
	}
	if state.SSOProviders == nil {
		state.SSOProviders = map[string]domain.SSOProvider{}
	}
	if state.IdentityLinks == nil {
		state.IdentityLinks = map[string]domain.UserIdentityLink{}
	}
	if state.SSOSessions == nil {
		state.SSOSessions = map[string]domain.SSOSession{}
	}
	if state.SSOSessionHashes == nil {
		state.SSOSessionHashes = map[string]string{}
	}
	if state.APIKeys == nil {
		state.APIKeys = map[string]domain.APIKey{}
	}
	if state.APIKeyHashes == nil {
		state.APIKeyHashes = map[string]string{}
	}
	if state.Collectors == nil {
		state.Collectors = map[string]domain.Collector{}
	}
	if state.CollectorReleases == nil {
		state.CollectorReleases = map[string]domain.CollectorRelease{}
	}
	if state.Products == nil {
		state.Products = map[string]domain.Product{}
	}
	if state.Projects == nil {
		state.Projects = map[string]domain.Project{}
	}
	if state.Releases == nil {
		state.Releases = map[string]domain.Release{}
	}
	if state.Artifacts == nil {
		state.Artifacts = map[string]domain.Artifact{}
	}
	if state.BuildRuns == nil {
		state.BuildRuns = map[string]domain.BuildRun{}
	}
	if state.BuildAttestations == nil {
		state.BuildAttestations = map[string]domain.BuildAttestation{}
	}
	if state.Evidence == nil {
		state.Evidence = map[string]domain.EvidenceItem{}
	}
	if state.EvidenceLifecycle == nil {
		state.EvidenceLifecycle = map[string]domain.EvidenceLifecycleEvent{}
	}
	if state.ReleaseCandidates == nil {
		state.ReleaseCandidates = map[string]domain.ReleaseCandidate{}
	}
	if state.ContainerImages == nil {
		state.ContainerImages = map[string]domain.ContainerImage{}
	}
	if state.ArtifactSignatures == nil {
		state.ArtifactSignatures = map[string]domain.ArtifactSignature{}
	}
	if state.Repositories == nil {
		state.Repositories = map[string]domain.SourceRepository{}
	}
	if state.Commits == nil {
		state.Commits = map[string]domain.SourceCommit{}
	}
	if state.Branches == nil {
		state.Branches = map[string]domain.SourceBranch{}
	}
	if state.PullRequests == nil {
		state.PullRequests = map[string]domain.PullRequest{}
	}
	if state.Environments == nil {
		state.Environments = map[string]domain.DeploymentEnvironment{}
	}
	if state.Deployments == nil {
		state.Deployments = map[string]domain.DeploymentEvent{}
	}
	if state.Incidents == nil {
		state.Incidents = map[string]domain.Incident{}
	}
	if state.TimelineEvents == nil {
		state.TimelineEvents = map[string]domain.IncidentTimelineEvent{}
	}
	if state.IncidentWebhookReceivers == nil {
		state.IncidentWebhookReceivers = map[string]domain.IncidentWebhookReceiver{}
	}
	if state.IncidentWebhookEvents == nil {
		state.IncidentWebhookEvents = map[string]domain.IncidentWebhookEvent{}
	}
	if state.RemediationTasks == nil {
		state.RemediationTasks = map[string]domain.RemediationTask{}
	}
	if state.SecurityScans == nil {
		state.SecurityScans = map[string]domain.SecurityScan{}
	}
	if state.ManualSecurityDocs == nil {
		state.ManualSecurityDocs = map[string]domain.ManualSecurityDocument{}
	}
	if state.SBOMDiffs == nil {
		state.SBOMDiffs = map[string]domain.SBOMDiff{}
	}
	if state.DependencyChanges == nil {
		state.DependencyChanges = map[string]domain.DependencyChange{}
	}
	if state.VulnerabilityWorkflow == nil {
		state.VulnerabilityWorkflow = map[string]domain.VulnerabilityWorkflowRecord{}
	}
	if state.ContractDiffs == nil {
		state.ContractDiffs = map[string]domain.ContractDiff{}
	}
	if state.CustomPolicies == nil {
		state.CustomPolicies = map[string]domain.CustomPolicy{}
	}
	if state.CustomPolicyEvaluations == nil {
		state.CustomPolicyEvaluations = map[string]domain.CustomPolicyEvaluation{}
	}
	if state.Waivers == nil {
		state.Waivers = map[string]domain.Waiver{}
	}
	if state.Approvals == nil {
		state.Approvals = map[string]domain.ApprovalRecord{}
	}
	if state.RedactionProfiles == nil {
		state.RedactionProfiles = map[string]domain.RedactionProfile{}
	}
	if state.CustomerPackages == nil {
		state.CustomerPackages = map[string]domain.CustomerSecurityPackage{}
	}
	if state.HTMLReports == nil {
		state.HTMLReports = map[string]domain.HTMLReportPackage{}
	}
	if state.ReportTemplates == nil {
		state.ReportTemplates = map[string]domain.CustomReportTemplate{}
	}
	if state.RenderedReports == nil {
		state.RenderedReports = map[string]domain.RenderedCustomReport{}
	}
	if state.EvidenceBundles == nil {
		state.EvidenceBundles = map[string]domain.EvidenceBundle{}
	}
	if state.BundleImports == nil {
		state.BundleImports = map[string]domain.EvidenceBundleImport{}
	}
	if state.DSSETrustRoots == nil {
		state.DSSETrustRoots = map[string]domain.DSSETrustRoot{}
	}
	if state.CosignVerifications == nil {
		state.CosignVerifications = map[string]domain.CosignVerification{}
	}
	if state.SigningProviders == nil {
		state.SigningProviders = map[string]domain.SigningProvider{}
	}
	if state.MerkleBatches == nil {
		state.MerkleBatches = map[string]domain.MerkleBatch{}
	}
	if state.TransparencyCheckpoints == nil {
		state.TransparencyCheckpoints = map[string]domain.TransparencyCheckpoint{}
	}
	if state.ObjectRetentionPolicies == nil {
		state.ObjectRetentionPolicies = map[string]domain.ObjectRetentionPolicy{}
	}
	for id, policy := range state.ObjectRetentionPolicies {
		if policy.MaxVerificationAgeHours == 0 {
			policy.MaxVerificationAgeHours = defaultRetentionVerificationAgeHours
		}
		if policy.SchemaVersion != domain.ObjectRetentionPolicyVersion {
			if policy.Status == "verified" {
				policy.Status = "not_verified"
				policy.VerificationLimitations = append(policy.VerificationLimitations, "Legacy retention verification did not record complete provider observation metadata and is not treated as current provider enforcement.")
			}
			policy.SchemaVersion = domain.ObjectRetentionPolicyVersion
		}
		state.ObjectRetentionPolicies[id] = policy
	}
	if state.BackupManifests == nil {
		state.BackupManifests = map[string]domain.BackupManifest{}
	}
	if state.LegalHolds == nil {
		state.LegalHolds = map[string]domain.LegalHold{}
	}
	if state.RetentionOverrides == nil {
		state.RetentionOverrides = map[string]domain.RetentionOverride{}
	}
	if state.CustomerPortalAccess == nil {
		state.CustomerPortalAccess = map[string]domain.CustomerPortalAccess{}
	}
	if state.CustomerPortalHashes == nil {
		state.CustomerPortalHashes = map[string]string{}
	}
	if state.QuestionnaireTemplates == nil {
		state.QuestionnaireTemplates = map[string]domain.QuestionnaireTemplate{}
	}
	if state.QuestionnairePackages == nil {
		state.QuestionnairePackages = map[string]domain.QuestionnairePackage{}
	}
	if state.QuestionnaireAnswerLibrary == nil {
		state.QuestionnaireAnswerLibrary = map[string]domain.QuestionnaireAnswerLibraryEntry{}
	}
	if state.CommercialCollectors == nil {
		state.CommercialCollectors = map[string]domain.CommercialCollectorDefinition{}
	}
	if state.EvidenceSummaries == nil {
		state.EvidenceSummaries = map[string]domain.EvidenceSummary{}
	}
	if state.QuestionnaireDrafts == nil {
		state.QuestionnaireDrafts = map[string]domain.QuestionnaireDraft{}
	}
	if state.GraphSnapshots == nil {
		state.GraphSnapshots = map[string]domain.EvidenceGraphSnapshot{}
	}
	if state.SaaSProfiles == nil {
		state.SaaSProfiles = map[string]domain.SaaSEditionProfile{}
	}
	if state.PublicTransparencyLogs == nil {
		state.PublicTransparencyLogs = map[string]domain.PublicTransparencyLog{}
	}
	if state.PublicTransparencyItems == nil {
		state.PublicTransparencyItems = map[string]domain.PublicTransparencyLogEntry{}
	}
	if state.MarketplaceCollectors == nil {
		state.MarketplaceCollectors = map[string]domain.MarketplaceCollector{}
	}
	if state.PDFReports == nil {
		state.PDFReports = map[string]domain.PDFReportPackage{}
	}
	if state.AnomalyReports == nil {
		state.AnomalyReports = map[string]domain.AnomalyReport{}
	}
	if state.ProviderVerifications == nil {
		state.ProviderVerifications = map[string]domain.ProviderVerification{}
	}
	if state.SigningOperations == nil {
		state.SigningOperations = map[string]domain.SigningOperation{}
	}
	if state.ControlFrameworks == nil {
		state.ControlFrameworks = map[string]domain.ControlFramework{}
	}
	if state.SecurityControls == nil {
		state.SecurityControls = map[string]domain.SecurityControl{}
	}
	if state.ControlEvidence == nil {
		state.ControlEvidence = map[string]domain.ControlEvidence{}
	}
	if state.SBOMs == nil {
		state.SBOMs = map[string]domain.SBOM{}
	}
	if state.Scans == nil {
		state.Scans = map[string]domain.VulnerabilityScan{}
	}
	if state.VEXDocuments == nil {
		state.VEXDocuments = map[string]domain.VEXDocument{}
	}
	if state.VEXImportReports == nil {
		state.VEXImportReports = map[string]domain.VEXImportReport{}
	}
	if state.Decisions == nil {
		state.Decisions = map[string]domain.VulnerabilityDecision{}
	}
	if state.Contracts == nil {
		state.Contracts = map[string]domain.OpenAPIContract{}
	}
	if state.Policies == nil {
		state.Policies = map[string]domain.PolicyEvaluation{}
	}
	if state.Exceptions == nil {
		state.Exceptions = map[string]domain.Exception{}
	}
	if state.Bundles == nil {
		state.Bundles = map[string]domain.ReleaseBundle{}
	}
	if state.SigningKeys == nil {
		state.SigningKeys = map[string]domain.SigningKey{}
	}
	if state.SigningKeyPrivate == nil {
		state.SigningKeyPrivate = map[string][]byte{}
	}
	if state.Signatures == nil {
		state.Signatures = map[string]domain.Signature{}
	}
	if state.Verifications == nil {
		state.Verifications = map[string]domain.VerificationResult{}
	}
	if state.Chain == nil {
		state.Chain = map[string][]domain.AuditChainEntry{}
	}
	if state.Idempotency == nil {
		state.Idempotency = map[string]IdempotencyRecord{}
	}
	return state
}
