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

type ObjectStore interface {
	Put(context.Context, Object) error
	Get(context.Context, string) (Object, error)
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

type TransparencyProofFetcher interface {
	FetchTransparencyProof(context.Context, TransparencyProofRequest) (TransparencyProofResult, error)
}

type Outbox interface {
	Enqueue(context.Context, OutboxJob) error
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
	TenantID      string
	ObjectPrefix  string
	ObjectKey     string
	Mode          string
	RetentionDays int
}

type ObjectRetentionResult struct {
	Provider    string
	Enforced    bool
	Checks      []domain.VerifyCheck
	Limitations []string
}

type PersistedState struct {
	Tenants                  map[string]domain.Tenant                        `json:"tenants"`
	Organizations            map[string]domain.Organization                  `json:"organizations"`
	Users                    map[string]domain.HumanUser                     `json:"users"`
	RoleBindings             map[string]domain.RoleBinding                   `json:"role_bindings"`
	SSOProviders             map[string]domain.SSOProvider                   `json:"sso_providers"`
	IdentityLinks            map[string]domain.UserIdentityLink              `json:"identity_links"`
	SSOSessions              map[string]domain.SSOSession                    `json:"sso_sessions"`
	SSOSessionHashes         map[string]string                               `json:"sso_session_hashes,omitempty"`
	APIKeys                  map[string]domain.APIKey                        `json:"api_keys"`
	APIKeyHashes             map[string]string                               `json:"api_key_hashes,omitempty"`
	Collectors               map[string]domain.Collector                     `json:"collectors"`
	CollectorReleases        map[string]domain.CollectorRelease              `json:"collector_releases"`
	Products                 map[string]domain.Product                       `json:"products"`
	Projects                 map[string]domain.Project                       `json:"projects"`
	Releases                 map[string]domain.Release                       `json:"releases"`
	Artifacts                map[string]domain.Artifact                      `json:"artifacts"`
	BuildRuns                map[string]domain.BuildRun                      `json:"build_runs"`
	BuildAttestations        map[string]domain.BuildAttestation              `json:"build_attestations"`
	Evidence                 map[string]domain.EvidenceItem                  `json:"evidence"`
	EvidenceLifecycle        map[string]domain.EvidenceLifecycleEvent        `json:"evidence_lifecycle"`
	ReleaseCandidates        map[string]domain.ReleaseCandidate              `json:"release_candidates"`
	ContainerImages          map[string]domain.ContainerImage                `json:"container_images"`
	ArtifactSignatures       map[string]domain.ArtifactSignature             `json:"artifact_signatures"`
	Repositories             map[string]domain.SourceRepository              `json:"repositories"`
	Commits                  map[string]domain.SourceCommit                  `json:"commits"`
	Branches                 map[string]domain.SourceBranch                  `json:"branches"`
	PullRequests             map[string]domain.PullRequest                   `json:"pull_requests"`
	Environments             map[string]domain.DeploymentEnvironment         `json:"environments"`
	Deployments              map[string]domain.DeploymentEvent               `json:"deployments"`
	Incidents                map[string]domain.Incident                      `json:"incidents"`
	TimelineEvents           map[string]domain.IncidentTimelineEvent         `json:"timeline_events"`
	IncidentWebhookReceivers map[string]domain.IncidentWebhookReceiver       `json:"incident_webhook_receivers"`
	IncidentWebhookEvents    map[string]domain.IncidentWebhookEvent          `json:"incident_webhook_events"`
	RemediationTasks         map[string]domain.RemediationTask               `json:"remediation_tasks"`
	SecurityScans            map[string]domain.SecurityScan                  `json:"security_scans"`
	ManualSecurityDocs       map[string]domain.ManualSecurityDocument        `json:"manual_security_docs"`
	SBOMDiffs                map[string]domain.SBOMDiff                      `json:"sbom_diffs"`
	DependencyChanges        map[string]domain.DependencyChange              `json:"dependency_changes"`
	VulnerabilityWorkflow    map[string]domain.VulnerabilityWorkflowRecord   `json:"vulnerability_workflow"`
	ContractDiffs            map[string]domain.ContractDiff                  `json:"contract_diffs"`
	CustomPolicies           map[string]domain.CustomPolicy                  `json:"custom_policies"`
	CustomPolicyEvaluations  map[string]domain.CustomPolicyEvaluation        `json:"custom_policy_evaluations"`
	Waivers                  map[string]domain.Waiver                        `json:"waivers"`
	Approvals                map[string]domain.ApprovalRecord                `json:"approvals"`
	RedactionProfiles        map[string]domain.RedactionProfile              `json:"redaction_profiles"`
	CustomerPackages         map[string]domain.CustomerSecurityPackage       `json:"customer_packages"`
	HTMLReports              map[string]domain.HTMLReportPackage             `json:"html_reports"`
	ReportTemplates          map[string]domain.CustomReportTemplate          `json:"report_templates"`
	RenderedReports          map[string]domain.RenderedCustomReport          `json:"rendered_reports"`
	EvidenceBundles          map[string]domain.EvidenceBundle                `json:"evidence_bundles"`
	BundleImports            map[string]domain.EvidenceBundleImport          `json:"bundle_imports"`
	DSSETrustRoots           map[string]domain.DSSETrustRoot                 `json:"dsse_trust_roots"`
	CosignVerifications      map[string]domain.CosignVerification            `json:"cosign_verifications"`
	SigningProviders         map[string]domain.SigningProvider               `json:"signing_providers"`
	MerkleBatches            map[string]domain.MerkleBatch                   `json:"merkle_batches"`
	TransparencyCheckpoints  map[string]domain.TransparencyCheckpoint        `json:"transparency_checkpoints"`
	ObjectRetentionPolicies  map[string]domain.ObjectRetentionPolicy         `json:"object_retention_policies"`
	BackupManifests          map[string]domain.BackupManifest                `json:"backup_manifests"`
	LegalHolds               map[string]domain.LegalHold                     `json:"legal_holds"`
	RetentionOverrides       map[string]domain.RetentionOverride             `json:"retention_overrides"`
	CustomerPortalAccess     map[string]domain.CustomerPortalAccess          `json:"customer_portal_access"`
	CustomerPortalHashes     map[string]string                               `json:"customer_portal_hashes,omitempty"`
	QuestionnaireTemplates   map[string]domain.QuestionnaireTemplate         `json:"questionnaire_templates"`
	QuestionnairePackages    map[string]domain.QuestionnairePackage          `json:"questionnaire_packages"`
	CommercialCollectors     map[string]domain.CommercialCollectorDefinition `json:"commercial_collectors"`
	EvidenceSummaries        map[string]domain.EvidenceSummary               `json:"evidence_summaries"`
	QuestionnaireDrafts      map[string]domain.QuestionnaireDraft            `json:"questionnaire_drafts"`
	GraphSnapshots           map[string]domain.EvidenceGraphSnapshot         `json:"graph_snapshots"`
	SaaSProfiles             map[string]domain.SaaSEditionProfile            `json:"saas_profiles"`
	PublicTransparencyLogs   map[string]domain.PublicTransparencyLog         `json:"public_transparency_logs"`
	PublicTransparencyItems  map[string]domain.PublicTransparencyLogEntry    `json:"public_transparency_items"`
	MarketplaceCollectors    map[string]domain.MarketplaceCollector          `json:"marketplace_collectors"`
	PDFReports               map[string]domain.PDFReportPackage              `json:"pdf_reports"`
	AnomalyReports           map[string]domain.AnomalyReport                 `json:"anomaly_reports"`
	ProviderVerifications    map[string]domain.ProviderVerification          `json:"provider_verifications"`
	SigningOperations        map[string]domain.SigningOperation              `json:"signing_operations"`
	ControlFrameworks        map[string]domain.ControlFramework              `json:"control_frameworks"`
	SecurityControls         map[string]domain.SecurityControl               `json:"security_controls"`
	ControlEvidence          map[string]domain.ControlEvidence               `json:"control_evidence"`
	SBOMs                    map[string]domain.SBOM                          `json:"sboms"`
	Scans                    map[string]domain.VulnerabilityScan             `json:"scans"`
	VEXDocuments             map[string]domain.VEXDocument                   `json:"vex_documents"`
	Decisions                map[string]domain.VulnerabilityDecision         `json:"vulnerability_decisions"`
	Contracts                map[string]domain.OpenAPIContract               `json:"contracts"`
	Policies                 map[string]domain.PolicyEvaluation              `json:"policies"`
	Exceptions               map[string]domain.Exception                     `json:"exceptions"`
	Bundles                  map[string]domain.ReleaseBundle                 `json:"bundles"`
	SigningKeys              map[string]domain.SigningKey                    `json:"signing_keys"`
	SigningKeyPrivate        map[string][]byte                               `json:"signing_key_private,omitempty"`
	Signatures               map[string]domain.Signature                     `json:"signatures"`
	Verifications            map[string]domain.VerificationResult            `json:"verifications"`
	Chain                    map[string][]domain.AuditChainEntry             `json:"chain"`
	Idempotency              map[string]IdempotencyRecord                    `json:"idempotency"`
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
	canonical, err := canonicalAnyHash(map[string]any{
		"tenant_id":           entry.TenantID,
		"sequence":            entry.Sequence,
		"entry_type":          entry.EntryType,
		"subject_type":        entry.SubjectType,
		"subject_id":          entry.SubjectID,
		"actor_type":          entry.ActorType,
		"actor_id":            entry.ActorID,
		"occurred_at":         entry.OccurredAt.UTC().Format(time.RFC3339Nano),
		"payload_hash":        entry.PayloadHash,
		"previous_entry_hash": entry.PreviousEntryHash,
		"signature_ref":       entry.SignatureRef,
		"schema_version":      entry.SchemaVersion,
	})
	if err != nil {
		return domain.AuditChainEntry{}, err
	}
	entry.CanonicalEntryHash = canonical
	entry.EntryHash = hashBytes([]byte(previous + "\n" + canonical))
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

type nopOutbox struct{}

func (nopOutbox) Enqueue(context.Context, OutboxJob) error { return nil }
