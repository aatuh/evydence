package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type Store interface {
	LoadState(context.Context) (PersistedState, bool, error)
	SaveState(context.Context, PersistedState) error
}

type CriticalMutationStore interface {
	ApplyCriticalMutation(context.Context, CriticalMutation) error
}

type ReleaseLedgerMutationStore interface {
	ApplyReleaseLedgerMutation(context.Context, ReleaseLedgerMutation) error
}

type RelationalStateStore interface {
	SaveRelationalState(context.Context, PersistedState) error
}

// AuditChainRelationalStateStore atomically reconciles audit-chain append
// sequences with the durable database and returns the committed chain state.
type AuditChainRelationalStateStore interface {
	SaveRelationalStateWithAuditChain(context.Context, PersistedState) (map[string][]domain.AuditChainEntry, error)
}

type AuditChainCriticalMutationStore interface {
	ApplyCriticalMutationWithAuditChain(context.Context, CriticalMutation) (map[string][]domain.AuditChainEntry, error)
}

type AuditChainReleaseLedgerMutationStore interface {
	ApplyReleaseLedgerMutationWithAuditChain(context.Context, ReleaseLedgerMutation) (map[string][]domain.AuditChainEntry, error)
}

type ObjectStore interface {
	Put(context.Context, Object) error
	Get(context.Context, string) (Object, error)
}

// ReadinessCheck is a bounded, process-level dependency probe. Check must
// honor its context and must not return raw credentials, URLs, paths, tenant
// data, or provider responses in FailureDetail; public readiness never emits
// either the returned error or FailureDetail.
type ReadinessCheck struct {
	Name          string
	Timeout       time.Duration
	FailureDetail string
	Check         func(context.Context) error
}

type ObjectRetentionVerifier interface {
	VerifyObjectRetention(context.Context, ObjectRetentionRequest) (ObjectRetentionResult, error)
}

type SigningExecutor interface {
	Sign(context.Context, SigningRequest) (SigningResult, error)
}

type OIDCDiscoveryClient interface {
	FetchOIDCTrustMaterial(context.Context, OIDCDiscoveryRequest) (OIDCDiscoveryResult, error)
}

type ProviderIdentityValidator interface {
	ValidateProviderIdentity(context.Context, ProviderIdentityValidationRequest) (ProviderIdentityValidationResult, error)
}

type TransparencyProofFetcher interface {
	FetchTransparencyProof(context.Context, TransparencyProofRequest) (TransparencyProofResult, error)
}

type Outbox interface {
	Enqueue(context.Context, OutboxJob) error
}

// UnitOfWorkFactory begins a single command transaction. Application commands
// use its focused repositories rather than aggregating and saving the full
// persisted ledger state.
type UnitOfWorkFactory interface {
	BeginUnitOfWork(context.Context) (UnitOfWork, error)
}

// UnitOfWork owns one command transaction. Commit publishes every repository
// mutation together. Rollback discards all uncommitted work and is safe to call
// after a failed command.
type UnitOfWork interface {
	Repositories() Repositories
	Commit(context.Context) error
	Rollback(context.Context) error
}

// Repositories are transaction-scoped persistence ports. The ports deliberately
// expose bounded contexts rather than PersistedState so application services
// cannot accidentally perform a whole-ledger write.
type Repositories struct {
	Identity       IdentityRepository
	ReleaseCatalog ReleaseCatalogRepository
	Evidence       EvidenceRepository
	Decisions      DecisionRepository
	Audit          AuditRepository
	Idempotency    IdempotencyRepository
	Outbox         OutboxRepository
	Controls       ControlRepository
	Governance     GovernanceRepository
	Builds         BuildRepository
	SupplyChain    SupplyChainRepository
	Source         SourceRepository
	Deployments    DeploymentRepository
	Packages       PackageRepository
	Signatures     SignatureRepository
	Integrity      IntegrityRepository
	Verification   VerificationRepository
	Enterprise     EnterpriseRepository
	Future         FutureExtensionsRepository
}

type IdentityRepository interface {
	InsertTenant(context.Context, domain.Tenant) error
	InsertAPIKey(context.Context, domain.APIKey) error
	UpdateAPIKeyLastUsed(context.Context, domain.APIKey) error
	UpdateCollectorLastSeen(context.Context, domain.Collector) error
	InsertOrganization(context.Context, domain.Organization) error
	InsertHumanUser(context.Context, domain.HumanUser) error
	DeactivateHumanUser(context.Context, domain.HumanUser) error
	InsertRoleBinding(context.Context, domain.RoleBinding) error
	InsertSSOProvider(context.Context, domain.SSOProvider) error
	UpdateSSOProviderTrustMaterial(context.Context, domain.SSOProvider) error
	InsertUserIdentityLink(context.Context, domain.UserIdentityLink) error
	InsertProviderVerification(context.Context, domain.ProviderVerification) error
	InsertSSOSession(context.Context, domain.SSOSession) error
	ValidateActiveSSOSession(context.Context, domain.SSOSession, time.Time) error
	RevokeSSOSession(context.Context, domain.SSOSession) error
	InsertCustomerPortalAccess(context.Context, domain.CustomerPortalAccess) error
	UpdateCustomerPortalAccess(context.Context, domain.CustomerPortalAccess, domain.CustomerPortalAccess) error
}

type ReleaseCatalogRepository interface {
	InsertProduct(context.Context, domain.Product) error
	InsertProject(context.Context, domain.Project) error
	InsertRelease(context.Context, domain.Release) error
	UpdateReleaseState(context.Context, domain.Release, string) error
	InsertArtifact(context.Context, domain.Artifact) error
	InsertReleaseCandidate(context.Context, domain.ReleaseCandidate) error
	UpdateReleaseCandidateState(context.Context, domain.ReleaseCandidate, string) error
}

type EvidenceRepository interface {
	InsertEvidence(context.Context, domain.EvidenceItem) error
	UpdateEvidenceLinks(context.Context, domain.EvidenceItem) error
	RecordSupersession(context.Context, domain.EvidenceItem, domain.EvidenceItem) error
	AppendLifecycle(context.Context, domain.EvidenceLifecycleEvent) error
	InsertSBOM(context.Context, domain.SBOM) error
	InsertVulnerabilityScan(context.Context, domain.VulnerabilityScan) error
	InsertOpenAPIContract(context.Context, domain.OpenAPIContract) error
	InsertVEXDocument(context.Context, domain.VEXDocument) error
	InsertVEXImportReport(context.Context, domain.VEXImportReport) error
}

type DecisionRepository interface {
	InsertVulnerabilityDecision(context.Context, domain.VulnerabilityDecision) error
	SupersedeAndInsert(context.Context, domain.VulnerabilityDecision, []domain.VulnerabilityDecision) error
	InsertException(context.Context, domain.Exception) error
	ApproveException(context.Context, domain.Exception) error
}

type AuditRepository interface {
	Append(context.Context, domain.AuditChainEntry) (domain.AuditChainEntry, error)
}

type IdempotencyRepository interface {
	Insert(context.Context, IdempotencyRecordKey, IdempotencyRecord) error
}

type OutboxRepository interface {
	Enqueue(context.Context, OutboxJob) error
}

type ControlRepository interface {
	InsertControlFramework(context.Context, domain.ControlFramework) error
	InsertSecurityControl(context.Context, domain.SecurityControl) error
	InsertControlEvidence(context.Context, domain.ControlEvidence) error
}

type GovernanceRepository interface {
	InsertWaiver(context.Context, domain.Waiver) error
	ApproveWaiver(context.Context, domain.Waiver) error
	InsertApprovalRecord(context.Context, domain.ApprovalRecord) error
	InsertRedactionProfile(context.Context, domain.RedactionProfile) error
	InsertLegalHold(context.Context, domain.LegalHold) error
	InsertRetentionOverride(context.Context, domain.RetentionOverride) error
	InsertDSSETrustRoot(context.Context, domain.DSSETrustRoot) error
}

type BuildRepository interface {
	InsertCollector(context.Context, domain.Collector) error
	InsertCollectorRelease(context.Context, domain.CollectorRelease) error
	InsertBuildRun(context.Context, domain.BuildRun) error
	InsertBuildAttestation(context.Context, domain.BuildAttestation) error
}

type SupplyChainRepository interface {
	InsertContainerImage(context.Context, domain.ContainerImage) error
	InsertArtifactSignature(context.Context, domain.ArtifactSignature) error
}

type SourceRepository interface {
	InsertSourceRepository(context.Context, domain.SourceRepository) error
	InsertSourceCommit(context.Context, domain.SourceCommit) error
	InsertSourceBranch(context.Context, domain.SourceBranch) error
	UpdateSourceBranch(context.Context, domain.SourceBranch) error
	InsertPullRequest(context.Context, domain.PullRequest) error
}

type DeploymentRepository interface {
	InsertDeploymentEnvironment(context.Context, domain.DeploymentEnvironment) error
	InsertDeploymentEvent(context.Context, domain.DeploymentEvent) error
}

type PackageRepository interface {
	InsertReleaseBundle(context.Context, domain.ReleaseBundle) error
}

type SignatureRepository interface {
	InsertSigningKey(context.Context, domain.SigningKey) error
	UpdateSigningKey(context.Context, domain.SigningKey, string) error
	InsertSignature(context.Context, domain.Signature) error
}

type IntegrityRepository interface {
	InsertCosignVerification(context.Context, domain.CosignVerification) error
	InsertSigningProvider(context.Context, domain.SigningProvider) error
	InsertObjectRetentionPolicy(context.Context, domain.ObjectRetentionPolicy) error
	UpdateObjectRetentionPolicy(context.Context, domain.ObjectRetentionPolicy, string) error
	InsertBackupManifest(context.Context, domain.BackupManifest) error
	InsertMerkleBatch(context.Context, domain.MerkleBatch) error
	InsertTransparencyCheckpoint(context.Context, domain.TransparencyCheckpoint) error
}

type VerificationRepository interface {
	InsertVerificationResult(context.Context, domain.VerificationResult) error
	InsertPolicyEvaluation(context.Context, domain.PolicyEvaluation) error
}

type EnterpriseRepository interface {
	InsertCommercialCollectorDefinition(context.Context, domain.CommercialCollectorDefinition) error
	InsertQuestionnaireTemplate(context.Context, domain.QuestionnaireTemplate) error
	InsertQuestionnaireAnswerLibraryEntry(context.Context, domain.QuestionnaireAnswerLibraryEntry) error
	InsertQuestionnairePackage(context.Context, domain.QuestionnairePackage) error
}

type FutureExtensionsRepository interface {
	InsertPublicTransparencyLog(context.Context, domain.PublicTransparencyLog) error
	InsertPublicTransparencyLogEntry(context.Context, domain.PublicTransparencyLogEntry) error
	UpdatePublicTransparencyLogEntry(context.Context, domain.PublicTransparencyLogEntry, string) error
	InsertEvidenceSummary(context.Context, domain.EvidenceSummary) error
	InsertEvidenceGraphSnapshot(context.Context, domain.EvidenceGraphSnapshot) error
	InsertSaaSEditionProfile(context.Context, domain.SaaSEditionProfile) error
	InsertMarketplaceCollector(context.Context, domain.MarketplaceCollector) error
	InsertPDFReportPackage(context.Context, domain.PDFReportPackage) error
	InsertQuestionnaireDraft(context.Context, domain.QuestionnaireDraft) error
	InsertAnomalyReport(context.Context, domain.AnomalyReport) error
	InsertSigningOperation(context.Context, domain.Signature, domain.SigningOperation) error
}

type SigningRequest struct {
	TenantID     string
	ProviderID   string
	ProviderType string
	KeyRef       string
	SubjectType  string
	SubjectID    string
	PayloadHash  string
}

type SigningResult struct {
	Signature string
	KeyID     string
	Algorithm string
	Checks    []domain.VerifyCheck
}

type OIDCDiscoveryRequest struct {
	TenantID   string
	ProviderID string
	Issuer     string
}

type OIDCDiscoveryResult struct {
	Issuer      string
	JWKS        map[string]any
	Checks      []domain.VerifyCheck
	Limitations []string
}

type ProviderIdentityValidationRequest struct {
	TenantID     string
	ProviderID   string
	ProviderType string
	Issuer       string
	Subject      string
	GroupsClaim  string
	AccessToken  string
}

type ProviderIdentityValidationResult struct {
	Checks      []domain.VerifyCheck
	Groups      []string
	Limitations []string
}

type TransparencyProofRequest struct {
	TenantID   string
	LogID      string
	EntryID    string
	Endpoint   string
	ExternalID string
	EntryHash  string
}

type TransparencyProofResult struct {
	ExternalID     string
	LeafHash       string
	RootHash       string
	LeafIndex      int
	TreeSize       int
	InclusionProof []string
	Checks         []domain.VerifyCheck
	Limitations    []string
}

type ObjectRetentionRequest struct {
	TenantID         string
	ObjectPrefix     string
	ObjectKey        string
	Mode             string
	RetentionDays    int
	RequireLegalHold bool
}

type ObjectRetentionResult struct {
	Provider      string
	Bucket        string
	ObjectKey     string
	Mode          string
	RetentionDays int
	LegalHold     *bool
	ObservedAt    time.Time
	Enforced      bool
	Checks        []domain.VerifyCheck
	Limitations   []string
}

type PersistedState struct {
	Tenants                    map[string]domain.Tenant                          `json:"tenants"`
	Organizations              map[string]domain.Organization                    `json:"organizations"`
	Users                      map[string]domain.HumanUser                       `json:"users"`
	RoleBindings               map[string]domain.RoleBinding                     `json:"role_bindings"`
	SSOProviders               map[string]domain.SSOProvider                     `json:"sso_providers"`
	IdentityLinks              map[string]domain.UserIdentityLink                `json:"identity_links"`
	SSOSessions                map[string]domain.SSOSession                      `json:"sso_sessions"`
	SSOSessionHashes           map[string]string                                 `json:"sso_session_hashes,omitempty"`
	APIKeys                    map[string]domain.APIKey                          `json:"api_keys"`
	APIKeyHashes               map[string]string                                 `json:"api_key_hashes,omitempty"`
	Collectors                 map[string]domain.Collector                       `json:"collectors"`
	CollectorReleases          map[string]domain.CollectorRelease                `json:"collector_releases"`
	Products                   map[string]domain.Product                         `json:"products"`
	Projects                   map[string]domain.Project                         `json:"projects"`
	Releases                   map[string]domain.Release                         `json:"releases"`
	Artifacts                  map[string]domain.Artifact                        `json:"artifacts"`
	BuildRuns                  map[string]domain.BuildRun                        `json:"build_runs"`
	BuildAttestations          map[string]domain.BuildAttestation                `json:"build_attestations"`
	Evidence                   map[string]domain.EvidenceItem                    `json:"evidence"`
	EvidenceLifecycle          map[string]domain.EvidenceLifecycleEvent          `json:"evidence_lifecycle"`
	ReleaseCandidates          map[string]domain.ReleaseCandidate                `json:"release_candidates"`
	ContainerImages            map[string]domain.ContainerImage                  `json:"container_images"`
	ArtifactSignatures         map[string]domain.ArtifactSignature               `json:"artifact_signatures"`
	Repositories               map[string]domain.SourceRepository                `json:"repositories"`
	Commits                    map[string]domain.SourceCommit                    `json:"commits"`
	Branches                   map[string]domain.SourceBranch                    `json:"branches"`
	PullRequests               map[string]domain.PullRequest                     `json:"pull_requests"`
	Environments               map[string]domain.DeploymentEnvironment           `json:"environments"`
	Deployments                map[string]domain.DeploymentEvent                 `json:"deployments"`
	Incidents                  map[string]domain.Incident                        `json:"incidents"`
	TimelineEvents             map[string]domain.IncidentTimelineEvent           `json:"timeline_events"`
	IncidentWebhookReceivers   map[string]domain.IncidentWebhookReceiver         `json:"incident_webhook_receivers"`
	IncidentWebhookEvents      map[string]domain.IncidentWebhookEvent            `json:"incident_webhook_events"`
	RemediationTasks           map[string]domain.RemediationTask                 `json:"remediation_tasks"`
	SecurityScans              map[string]domain.SecurityScan                    `json:"security_scans"`
	ManualSecurityDocs         map[string]domain.ManualSecurityDocument          `json:"manual_security_docs"`
	SBOMDiffs                  map[string]domain.SBOMDiff                        `json:"sbom_diffs"`
	DependencyChanges          map[string]domain.DependencyChange                `json:"dependency_changes"`
	VulnerabilityWorkflow      map[string]domain.VulnerabilityWorkflowRecord     `json:"vulnerability_workflow"`
	ContractDiffs              map[string]domain.ContractDiff                    `json:"contract_diffs"`
	CustomPolicies             map[string]domain.CustomPolicy                    `json:"custom_policies"`
	CustomPolicyEvaluations    map[string]domain.CustomPolicyEvaluation          `json:"custom_policy_evaluations"`
	Waivers                    map[string]domain.Waiver                          `json:"waivers"`
	Approvals                  map[string]domain.ApprovalRecord                  `json:"approvals"`
	RedactionProfiles          map[string]domain.RedactionProfile                `json:"redaction_profiles"`
	CustomerPackages           map[string]domain.CustomerSecurityPackage         `json:"customer_packages"`
	HTMLReports                map[string]domain.HTMLReportPackage               `json:"html_reports"`
	ReportTemplates            map[string]domain.CustomReportTemplate            `json:"report_templates"`
	RenderedReports            map[string]domain.RenderedCustomReport            `json:"rendered_reports"`
	EvidenceBundles            map[string]domain.EvidenceBundle                  `json:"evidence_bundles"`
	BundleImports              map[string]domain.EvidenceBundleImport            `json:"bundle_imports"`
	DSSETrustRoots             map[string]domain.DSSETrustRoot                   `json:"dsse_trust_roots"`
	CosignVerifications        map[string]domain.CosignVerification              `json:"cosign_verifications"`
	SigningProviders           map[string]domain.SigningProvider                 `json:"signing_providers"`
	MerkleBatches              map[string]domain.MerkleBatch                     `json:"merkle_batches"`
	TransparencyCheckpoints    map[string]domain.TransparencyCheckpoint          `json:"transparency_checkpoints"`
	ObjectRetentionPolicies    map[string]domain.ObjectRetentionPolicy           `json:"object_retention_policies"`
	BackupManifests            map[string]domain.BackupManifest                  `json:"backup_manifests"`
	LegalHolds                 map[string]domain.LegalHold                       `json:"legal_holds"`
	RetentionOverrides         map[string]domain.RetentionOverride               `json:"retention_overrides"`
	CustomerPortalAccess       map[string]domain.CustomerPortalAccess            `json:"customer_portal_access"`
	CustomerPortalHashes       map[string]string                                 `json:"customer_portal_hashes,omitempty"`
	QuestionnaireTemplates     map[string]domain.QuestionnaireTemplate           `json:"questionnaire_templates"`
	QuestionnairePackages      map[string]domain.QuestionnairePackage            `json:"questionnaire_packages"`
	QuestionnaireAnswerLibrary map[string]domain.QuestionnaireAnswerLibraryEntry `json:"questionnaire_answer_library"`
	CommercialCollectors       map[string]domain.CommercialCollectorDefinition   `json:"commercial_collectors"`
	EvidenceSummaries          map[string]domain.EvidenceSummary                 `json:"evidence_summaries"`
	QuestionnaireDrafts        map[string]domain.QuestionnaireDraft              `json:"questionnaire_drafts"`
	GraphSnapshots             map[string]domain.EvidenceGraphSnapshot           `json:"graph_snapshots"`
	SaaSProfiles               map[string]domain.SaaSEditionProfile              `json:"saas_profiles"`
	PublicTransparencyLogs     map[string]domain.PublicTransparencyLog           `json:"public_transparency_logs"`
	PublicTransparencyItems    map[string]domain.PublicTransparencyLogEntry      `json:"public_transparency_items"`
	MarketplaceCollectors      map[string]domain.MarketplaceCollector            `json:"marketplace_collectors"`
	PDFReports                 map[string]domain.PDFReportPackage                `json:"pdf_reports"`
	AnomalyReports             map[string]domain.AnomalyReport                   `json:"anomaly_reports"`
	ProviderVerifications      map[string]domain.ProviderVerification            `json:"provider_verifications"`
	SigningOperations          map[string]domain.SigningOperation                `json:"signing_operations"`
	ControlFrameworks          map[string]domain.ControlFramework                `json:"control_frameworks"`
	SecurityControls           map[string]domain.SecurityControl                 `json:"security_controls"`
	ControlEvidence            map[string]domain.ControlEvidence                 `json:"control_evidence"`
	SBOMs                      map[string]domain.SBOM                            `json:"sboms"`
	Scans                      map[string]domain.VulnerabilityScan               `json:"scans"`
	VEXDocuments               map[string]domain.VEXDocument                     `json:"vex_documents"`
	VEXImportReports           map[string]domain.VEXImportReport                 `json:"vex_import_reports"`
	Decisions                  map[string]domain.VulnerabilityDecision           `json:"vulnerability_decisions"`
	Contracts                  map[string]domain.OpenAPIContract                 `json:"contracts"`
	Policies                   map[string]domain.PolicyEvaluation                `json:"policies"`
	Exceptions                 map[string]domain.Exception                       `json:"exceptions"`
	Bundles                    map[string]domain.ReleaseBundle                   `json:"bundles"`
	SigningKeys                map[string]domain.SigningKey                      `json:"signing_keys"`
	SigningKeyPrivate          map[string][]byte                                 `json:"signing_key_private,omitempty"`
	Signatures                 map[string]domain.Signature                       `json:"signatures"`
	Verifications              map[string]domain.VerificationResult              `json:"verifications"`
	Chain                      map[string][]domain.AuditChainEntry               `json:"chain"`
	Idempotency                map[string]IdempotencyRecord                      `json:"idempotency"`
}

func AppendPersistedChainEntry(state *PersistedState, now time.Time, tenantID, entryType, subjectType, subjectID, actorType, actorID, payloadHash, signatureRef string) (domain.AuditChainEntry, error) {
	if state.Chain == nil {
		state.Chain = map[string][]domain.AuditChainEntry{}
	}
	entries := state.Chain[tenantID]
	previous := ""
	if len(entries) > 0 {
		previous = entries[len(entries)-1].EntryHash
	}
	entry := domain.AuditChainEntry{
		ID:                newID("ace"),
		TenantID:          tenantID,
		Sequence:          int64(len(entries) + 1),
		EntryType:         entryType,
		SubjectType:       subjectType,
		SubjectID:         subjectID,
		ActorType:         actorType,
		ActorID:           actorID,
		OccurredAt:        now.UTC(),
		PayloadHash:       payloadHash,
		PreviousEntryHash: previous,
		SignatureRef:      signatureRef,
		SchemaVersion:     domain.AuditChainEntrySchemaVersion,
	}
	if err := RehashAuditChainEntry(&entry); err != nil {
		return domain.AuditChainEntry{}, err
	}
	state.Chain[tenantID] = append(entries, entry)
	return entry, nil
}

type IdempotencyRecord struct {
	RequestHash string    `json:"request_hash"`
	Status      int       `json:"status"`
	Response    any       `json:"response"`
	CreatedAt   time.Time `json:"created_at"`
}

type IdempotencyRecordKey struct {
	TenantID       string
	ActorID        string
	Method         string
	Path           string
	IdempotencyKey string
}

type Object struct {
	Key       string
	TenantID  string
	MediaType string
	Digest    string
	Bytes     []byte
	CreatedAt time.Time
}

type OutboxJob struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	Kind        string         `json:"kind"`
	SubjectType string         `json:"subject_type"`
	SubjectID   string         `json:"subject_id"`
	Payload     map[string]any `json:"payload,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

type CriticalMutation struct {
	Tenants                []domain.Tenant
	APIKeys                []domain.APIKey
	APIKeyHashes           map[string]string
	Collectors             []domain.Collector
	SSOSessions            []domain.SSOSession
	SSOSessionHashes       map[string]string
	CustomerPortalAccess   []domain.CustomerPortalAccess
	CustomerPortalHashes   map[string]string
	Idempotency            map[string]IdempotencyRecord
	SigningKeys            []domain.SigningKey
	SigningKeyPrivate      map[string][]byte
	Signatures             []domain.Signature
	ReleaseBundles         []domain.ReleaseBundle
	VerificationResults    []domain.VerificationResult
	ProviderVerifications  []domain.ProviderVerification
	VulnerabilityDecisions []domain.VulnerabilityDecision
	AuditChainEntries      []domain.AuditChainEntry
	OutboxJobs             []OutboxJob
}

type ReleaseLedgerMutation struct {
	Products               []domain.Product
	Projects               []domain.Project
	Releases               []domain.Release
	Artifacts              []domain.Artifact
	Evidence               []domain.EvidenceItem
	EvidenceLifecycle      []domain.EvidenceLifecycleEvent
	SBOMs                  []domain.SBOM
	Scans                  []domain.VulnerabilityScan
	Contracts              []domain.OpenAPIContract
	VEXDocuments           []domain.VEXDocument
	VEXImportReports       []domain.VEXImportReport
	VulnerabilityDecisions []domain.VulnerabilityDecision
	AuditChainEntries      []domain.AuditChainEntry
	OutboxJobs             []OutboxJob
}

type nopOutbox struct{}

func (nopOutbox) Enqueue(context.Context, OutboxJob) error { return nil }
