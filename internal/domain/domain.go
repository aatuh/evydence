package domain

import "time"

const (
	EvidenceItemSchemaVersion       = "evidence-item.v1.0.0"
	AuditChainEntrySchemaVersion    = "audit-chain-entry.v1.0.0"
	ReleaseBundleSchemaVersion      = "release-bundle.v1.0.0"
	CanonicalizationProfileVersion  = "canonicalization-profile.v1.0.0"
	PolicySetVersion                = "policy-set.v1.0.0"
	VEXDocumentSchemaVersion        = "vex-document.v1.0.0"
	VulnerabilityDecisionVersion    = "vulnerability-decision.v1.0.0"
	ReleaseReadinessTemplateVersion = "release-readiness.v1.0.0"
	CollectorSchemaVersion          = "collector.v1.0.0"
	BuildRunSchemaVersion           = "build-run.v1.0.0"
	BuildAttestationSchemaVersion   = "build-attestation.v1.0.0"
	ControlFrameworkSchemaVersion   = "control-framework.v1.0.0"
	SecurityControlSchemaVersion    = "security-control.v1.0.0"
	ControlEvidenceSchemaVersion    = "control-evidence.v1.0.0"
	ControlCoverageTemplateVersion  = "control-coverage.v1.0.0"
	CRAReadinessTemplateVersion     = "cra-readiness.v1.0.0"
	EvidenceLifecycleSchemaVersion  = "evidence-lifecycle-event.v1.0.0"
	ReleaseCandidateSchemaVersion   = "release-candidate.v1.0.0"
	ContainerImageSchemaVersion     = "container-image.v1.0.0"
	ArtifactSignatureSchemaVersion  = "artifact-signature.v1.0.0"
	SourceRepositorySchemaVersion   = "source-repository.v1.0.0"
	SourceCommitSchemaVersion       = "source-commit.v1.0.0"
	SourceBranchSchemaVersion       = "source-branch.v1.0.0"
	PullRequestSchemaVersion        = "pull-request.v1.0.0"
	DeploymentEnvironmentVersion    = "deployment-environment.v1.0.0"
	DeploymentEventSchemaVersion    = "deployment-event.v1.0.0"
	IncidentSchemaVersion           = "incident.v1.0.0"
	IncidentTimelineSchemaVersion   = "incident-timeline-event.v1.0.0"
	RemediationTaskSchemaVersion    = "remediation-task.v1.0.0"
	SecurityScanSchemaVersion       = "security-scan.v1.0.0"
	ManualSecurityDocSchemaVersion  = "manual-security-document.v1.0.0"
	SBOMDiffSchemaVersion           = "sbom-diff.v1.0.0"
	DependencyChangeSchemaVersion   = "dependency-change.v1.0.0"
	ContractDiffSchemaVersion       = "contract-diff.v1.0.0"
	CustomPolicySchemaVersion       = "custom-policy.v1.0.0"
	CustomPolicyEvalSchemaVersion   = "custom-policy-evaluation.v1.0.0"
)

type Actor struct {
	TenantID    string
	KeyID       string
	Name        string
	Scopes      []string
	CollectorID string
}

func (a Actor) HasScope(scope string) bool {
	for _, got := range a.Scopes {
		if got == scope || got == "*" {
			return true
		}
	}
	return false
}

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type APIKey struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Hash       string     `json:"-"`
}

type Collector struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	Name          string     `json:"name"`
	Type          string     `json:"type"`
	Version       string     `json:"version"`
	APIKeyID      string     `json:"api_key_id"`
	Status        string     `json:"status"`
	AllowedScopes []string   `json:"allowed_scopes"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	SchemaVersion string     `json:"schema_version"`
	CreatedAt     time.Time  `json:"created_at"`
}

type Product struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

type Project struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	ProductID string    `json:"product_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Release struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	ProductID  string     `json:"product_id"`
	Version    string     `json:"version"`
	State      string     `json:"state"`
	CreatedAt  time.Time  `json:"created_at"`
	FrozenAt   *time.Time `json:"frozen_at,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
}

type Artifact struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	MediaType string    `json:"media_type"`
	Size      int64     `json:"size"`
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"created_at"`
}

type BuildRun struct {
	ID              string         `json:"id"`
	TenantID        string         `json:"tenant_id"`
	ProjectID       string         `json:"project_id"`
	ReleaseID       string         `json:"release_id"`
	CollectorID     string         `json:"collector_id,omitempty"`
	Provider        string         `json:"provider"`
	CommitSHA       string         `json:"commit_sha"`
	Repository      string         `json:"repository,omitempty"`
	WorkflowRef     string         `json:"workflow_ref,omitempty"`
	RunID           string         `json:"run_id,omitempty"`
	RunAttempt      int            `json:"run_attempt,omitempty"`
	JobID           string         `json:"job_id,omitempty"`
	Actor           string         `json:"actor,omitempty"`
	Ref             string         `json:"ref,omitempty"`
	OIDCSubject     string         `json:"oidc_subject,omitempty"`
	Status          string         `json:"status"`
	StartedAt       time.Time      `json:"started_at"`
	FinishedAt      *time.Time     `json:"finished_at,omitempty"`
	ParametersHash  string         `json:"parameters_hash,omitempty"`
	EnvironmentHash string         `json:"environment_hash,omitempty"`
	SourceIdentity  map[string]any `json:"source_identity,omitempty"`
	Outputs         []BuildOutput  `json:"outputs,omitempty"`
	SchemaVersion   string         `json:"schema_version"`
	CreatedAt       time.Time      `json:"created_at"`
}

type BuildOutput struct {
	ArtifactID string `json:"artifact_id,omitempty"`
	Digest     string `json:"digest"`
}

type BuildAttestation struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	BuildID            string    `json:"build_id"`
	EvidenceID         string    `json:"evidence_id"`
	PayloadRef         string    `json:"payload_ref,omitempty"`
	PayloadHash        string    `json:"payload_hash"`
	PayloadSize        int64     `json:"payload_size"`
	PayloadType        string    `json:"payload_type"`
	PredicateType      string    `json:"predicate_type"`
	SubjectDigests     []string  `json:"subject_digests"`
	BuilderID          string    `json:"builder_id,omitempty"`
	BuildType          string    `json:"build_type,omitempty"`
	MaterialsCount     int       `json:"materials_count"`
	SignatureCount     int       `json:"signature_count"`
	VerificationStatus string    `json:"verification_status"`
	SchemaVersion      string    `json:"schema_version"`
	CreatedAt          time.Time `json:"created_at"`
}

type EvidenceItem struct {
	ID                  string           `json:"id"`
	TenantID            string           `json:"tenant_id"`
	ProductID           string           `json:"product_id,omitempty"`
	ProjectID           string           `json:"project_id,omitempty"`
	ReleaseID           string           `json:"release_id,omitempty"`
	BuildID             string           `json:"build_id,omitempty"`
	DeploymentID        string           `json:"deployment_id,omitempty"`
	Type                string           `json:"type"`
	Subtype             string           `json:"subtype,omitempty"`
	Title               string           `json:"title"`
	SourceSystem        string           `json:"source_system"`
	SourceIdentity      map[string]any   `json:"source_identity,omitempty"`
	CollectorID         string           `json:"collector_id,omitempty"`
	UploadedBy          string           `json:"uploaded_by,omitempty"`
	ObservedAt          time.Time        `json:"observed_at"`
	EvidenceVersion     int              `json:"evidence_version"`
	SchemaVersion       string           `json:"schema_version"`
	PayloadRef          string           `json:"payload_ref,omitempty"`
	PayloadHash         string           `json:"payload_hash"`
	PayloadMediaType    string           `json:"payload_media_type,omitempty"`
	PayloadSize         int64            `json:"payload_size,omitempty"`
	CanonicalHash       string           `json:"canonical_hash"`
	Canonicalization    string           `json:"canonicalization"`
	SubjectRefs         []SubjectRef     `json:"subject_refs,omitempty"`
	RelatedEvidenceRefs []EvidenceRef    `json:"related_evidence_refs,omitempty"`
	Supersedes          string           `json:"supersedes,omitempty"`
	SupersededBy        string           `json:"superseded_by,omitempty"`
	TrustLevel          string           `json:"trust_level"`
	VerificationStatus  string           `json:"verification_status"`
	SignatureRefs       []string         `json:"signature_refs,omitempty"`
	ChainEntryID        string           `json:"chain_entry_id"`
	Tags                []string         `json:"tags,omitempty"`
	Metadata            map[string]any   `json:"metadata,omitempty"`
	Warnings            []EvidenceNotice `json:"warnings,omitempty"`
	Limitations         []string         `json:"limitations,omitempty"`
	CreatedAt           time.Time        `json:"created_at"`
}

type SubjectRef struct {
	Type   string `json:"type"`
	ID     string `json:"id,omitempty"`
	Digest string `json:"digest,omitempty"`
}

type EvidenceRef struct {
	Type         string `json:"type"`
	ID           string `json:"id"`
	Relationship string `json:"relationship,omitempty"`
}

type EvidenceNotice struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type EvidenceLifecycleEvent struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	EvidenceID    string         `json:"evidence_id"`
	Action        string         `json:"action"`
	Reason        string         `json:"reason"`
	Details       map[string]any `json:"details,omitempty"`
	ReplacementID string         `json:"replacement_id,omitempty"`
	ActorID       string         `json:"actor_id"`
	SchemaVersion string         `json:"schema_version"`
	CreatedAt     time.Time      `json:"created_at"`
}

type ReleaseCandidate struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	ReleaseID     string     `json:"release_id"`
	Name          string     `json:"name"`
	State         string     `json:"state"`
	BuildIDs      []string   `json:"build_ids,omitempty"`
	ArtifactIDs   []string   `json:"artifact_ids,omitempty"`
	SBOMIDs       []string   `json:"sbom_ids,omitempty"`
	ScanIDs       []string   `json:"scan_ids,omitempty"`
	VEXIDs        []string   `json:"vex_ids,omitempty"`
	ContractIDs   []string   `json:"contract_ids,omitempty"`
	BundleIDs     []string   `json:"bundle_ids,omitempty"`
	SnapshotHash  string     `json:"snapshot_hash"`
	SchemaVersion string     `json:"schema_version"`
	CreatedAt     time.Time  `json:"created_at"`
	PromotedAt    *time.Time `json:"promoted_at,omitempty"`
	RejectedAt    *time.Time `json:"rejected_at,omitempty"`
}

type ContainerImage struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ArtifactID    string    `json:"artifact_id,omitempty"`
	Repository    string    `json:"repository"`
	Tag           string    `json:"tag,omitempty"`
	Digest        string    `json:"digest"`
	Platform      string    `json:"platform,omitempty"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
}

type ArtifactSignature struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	ArtifactID         string    `json:"artifact_id"`
	SubjectDigest      string    `json:"subject_digest"`
	Algorithm          string    `json:"algorithm"`
	KeyID              string    `json:"key_id,omitempty"`
	Signature          string    `json:"signature"`
	PayloadRef         string    `json:"payload_ref,omitempty"`
	PayloadHash        string    `json:"payload_hash,omitempty"`
	VerificationStatus string    `json:"verification_status"`
	SchemaVersion      string    `json:"schema_version"`
	CreatedAt          time.Time `json:"created_at"`
}

type SourceRepository struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ProjectID     string    `json:"project_id,omitempty"`
	Provider      string    `json:"provider"`
	FullName      string    `json:"full_name"`
	CloneURL      string    `json:"clone_url,omitempty"`
	DefaultBranch string    `json:"default_branch,omitempty"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
}

type SourceCommit struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	RepositoryID  string    `json:"repository_id"`
	SHA           string    `json:"sha"`
	Author        string    `json:"author,omitempty"`
	MessageHash   string    `json:"message_hash,omitempty"`
	CommittedAt   time.Time `json:"committed_at"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
}

type SourceBranch struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	RepositoryID   string    `json:"repository_id"`
	Name           string    `json:"name"`
	HeadCommitID   string    `json:"head_commit_id,omitempty"`
	Protected      bool      `json:"protected"`
	ProtectionHash string    `json:"protection_hash,omitempty"`
	SchemaVersion  string    `json:"schema_version"`
	CreatedAt      time.Time `json:"created_at"`
}

type PullRequest struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	RepositoryID   string    `json:"repository_id"`
	Provider       string    `json:"provider"`
	ProviderID     string    `json:"provider_id"`
	Title          string    `json:"title"`
	State          string    `json:"state"`
	SourceBranch   string    `json:"source_branch,omitempty"`
	TargetBranch   string    `json:"target_branch,omitempty"`
	HeadCommitID   string    `json:"head_commit_id,omitempty"`
	ReviewDecision string    `json:"review_decision,omitempty"`
	SchemaVersion  string    `json:"schema_version"`
	CreatedAt      time.Time `json:"created_at"`
}

type ControlFramework struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	Slug          string    `json:"slug"`
	Version       string    `json:"version"`
	Description   string    `json:"description,omitempty"`
	Status        string    `json:"status"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
}

type SecurityControl struct {
	ID                   string                       `json:"id"`
	TenantID             string                       `json:"tenant_id"`
	FrameworkID          string                       `json:"framework_id"`
	Code                 string                       `json:"code"`
	Title                string                       `json:"title"`
	Objective            string                       `json:"objective"`
	EvidenceRequirements []ControlEvidenceRequirement `json:"evidence_requirements,omitempty"`
	Applicability        []string                     `json:"applicability,omitempty"`
	Limitations          []string                     `json:"limitations,omitempty"`
	SchemaVersion        string                       `json:"schema_version"`
	CreatedAt            time.Time                    `json:"created_at"`
}

type ControlEvidenceRequirement struct {
	Type          string `json:"type"`
	FreshnessDays int    `json:"freshness_days,omitempty"`
	Required      bool   `json:"required"`
}

type ControlEvidence struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ControlID     string    `json:"control_id"`
	EvidenceType  string    `json:"evidence_type"`
	SubjectType   string    `json:"subject_type"`
	SubjectID     string    `json:"subject_id"`
	ProductID     string    `json:"product_id,omitempty"`
	ReleaseID     string    `json:"release_id,omitempty"`
	Confidence    string    `json:"confidence"`
	Notes         string    `json:"notes,omitempty"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
}

type ControlCoverageReport struct {
	ReportType         string                `json:"report_type"`
	TemplateVersion    string                `json:"template_version"`
	FrameworkID        string                `json:"framework_id"`
	ProductID          string                `json:"product_id,omitempty"`
	ReleaseID          string                `json:"release_id,omitempty"`
	Result             string                `json:"result"`
	Controls           []ControlCoverageItem `json:"controls"`
	MissingEvidence    []string              `json:"missing_evidence,omitempty"`
	AcceptedExceptions []Exception           `json:"accepted_exceptions,omitempty"`
	Assumptions        []string              `json:"assumptions"`
	Limitations        []string              `json:"limitations"`
	GeneratedAt        time.Time             `json:"generated_at"`
}

type ControlCoverageItem struct {
	ControlID      string            `json:"control_id"`
	Code           string            `json:"code"`
	Title          string            `json:"title"`
	Status         string            `json:"status"`
	Confidence     string            `json:"confidence"`
	LinkedEvidence []ControlEvidence `json:"linked_evidence,omitempty"`
	Missing        []string          `json:"missing,omitempty"`
	Explanation    string            `json:"explanation"`
	Limitations    []string          `json:"limitations,omitempty"`
}

type CRAReadinessReport struct {
	ReportType         string                `json:"report_type"`
	TemplateVersion    string                `json:"template_version"`
	ProductID          string                `json:"product_id"`
	ReleaseID          string                `json:"release_id,omitempty"`
	Result             string                `json:"result"`
	Controls           []ControlCoverageItem `json:"controls"`
	MissingEvidence    []string              `json:"missing_evidence,omitempty"`
	AcceptedExceptions []Exception           `json:"accepted_exceptions,omitempty"`
	Assumptions        []string              `json:"assumptions"`
	Limitations        []string              `json:"limitations"`
	GeneratedAt        time.Time             `json:"generated_at"`
}

type AuditChainEntry struct {
	ID                 string         `json:"id"`
	TenantID           string         `json:"tenant_id"`
	Sequence           int64          `json:"sequence"`
	EntryType          string         `json:"entry_type"`
	SubjectType        string         `json:"subject_type"`
	SubjectID          string         `json:"subject_id"`
	ActorType          string         `json:"actor_type"`
	ActorID            string         `json:"actor_id"`
	OccurredAt         time.Time      `json:"occurred_at"`
	RequestID          string         `json:"request_id,omitempty"`
	IdempotencyKey     string         `json:"idempotency_key,omitempty"`
	PayloadHash        string         `json:"payload_hash,omitempty"`
	CanonicalEntryHash string         `json:"canonical_entry_hash"`
	PreviousEntryHash  string         `json:"previous_entry_hash"`
	EntryHash          string         `json:"entry_hash"`
	SignatureRef       string         `json:"signature_ref,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	SchemaVersion      string         `json:"schema_version"`
}

type SigningKey struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	KID       string     `json:"kid"`
	Algorithm string     `json:"algorithm"`
	Status    string     `json:"status"`
	PublicKey string     `json:"public_key"`
	Private   []byte     `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type Signature struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	SubjectType string    `json:"subject_type"`
	SubjectID   string    `json:"subject_id"`
	KeyID       string    `json:"key_id"`
	Algorithm   string    `json:"algorithm"`
	Value       string    `json:"value"`
	CreatedAt   time.Time `json:"created_at"`
}

type SBOM struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	EvidenceID     string          `json:"evidence_id"`
	ReleaseID      string          `json:"release_id,omitempty"`
	ArtifactID     string          `json:"artifact_id,omitempty"`
	Format         string          `json:"format"`
	SpecVersion    string          `json:"spec_version"`
	ComponentCount int             `json:"component_count"`
	Components     []SBOMComponent `json:"components,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type SBOMComponent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type VulnerabilityScan struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	EvidenceID string                 `json:"evidence_id"`
	ReleaseID  string                 `json:"release_id,omitempty"`
	Scanner    string                 `json:"scanner"`
	TargetRef  string                 `json:"target_ref"`
	Summary    map[string]int         `json:"summary"`
	Findings   []VulnerabilityFinding `json:"findings,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

type VulnerabilityFinding struct {
	ID            string `json:"id"`
	Vulnerability string `json:"vulnerability"`
	Component     string `json:"component,omitempty"`
	Severity      string `json:"severity"`
	State         string `json:"state"`
}

type VEXDocument struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	EvidenceID     string         `json:"evidence_id"`
	ReleaseID      string         `json:"release_id,omitempty"`
	ArtifactID     string         `json:"artifact_id,omitempty"`
	Format         string         `json:"format"`
	Author         string         `json:"author"`
	Version        string         `json:"version,omitempty"`
	StatementCount int            `json:"statement_count"`
	StatusSummary  map[string]int `json:"status_summary"`
	SchemaVersion  string         `json:"schema_version"`
	CreatedAt      time.Time      `json:"created_at"`
}

type VulnerabilityDecision struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	FindingID       string    `json:"finding_id"`
	ScanID          string    `json:"scan_id"`
	ReleaseID       string    `json:"release_id,omitempty"`
	Vulnerability   string    `json:"vulnerability"`
	Component       string    `json:"component,omitempty"`
	Status          string    `json:"status"`
	Justification   string    `json:"justification"`
	ImpactStatement string    `json:"impact_statement,omitempty"`
	ActionStatement string    `json:"action_statement,omitempty"`
	Source          string    `json:"source"`
	EvidenceID      string    `json:"evidence_id,omitempty"`
	VEXDocumentID   string    `json:"vex_document_id,omitempty"`
	Supersedes      string    `json:"supersedes,omitempty"`
	SupersededBy    string    `json:"superseded_by,omitempty"`
	ApprovedBy      string    `json:"approved_by,omitempty"`
	SchemaVersion   string    `json:"schema_version"`
	CreatedAt       time.Time `json:"created_at"`
}

type OpenAPIContract struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	ProductID  string    `json:"product_id"`
	ReleaseID  string    `json:"release_id,omitempty"`
	Version    string    `json:"version"`
	Hash       string    `json:"hash"`
	PathCount  int       `json:"path_count"`
	EvidenceID string    `json:"evidence_id"`
	CreatedAt  time.Time `json:"created_at"`
}

type PolicyEvaluation struct {
	ID        string        `json:"id"`
	TenantID  string        `json:"tenant_id"`
	ReleaseID string        `json:"release_id"`
	Result    string        `json:"result"`
	PolicySet string        `json:"policy_set"`
	Checks    []PolicyCheck `json:"checks"`
	CreatedAt time.Time     `json:"created_at"`
}

type PolicyCheck struct {
	Name        string   `json:"name"`
	Result      string   `json:"result"`
	Severity    string   `json:"severity"`
	Missing     []string `json:"missing,omitempty"`
	Explanation string   `json:"explanation"`
}

type Exception struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	ReleaseID  string     `json:"release_id"`
	FindingID  string     `json:"finding_id,omitempty"`
	ControlID  string     `json:"control_id,omitempty"`
	Reason     string     `json:"reason"`
	Owner      string     `json:"owner"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Approved   bool       `json:"approved"`
	ApprovedBy string     `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type ReleaseBundle struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	ReleaseID     string         `json:"release_id"`
	State         string         `json:"state"`
	Manifest      map[string]any `json:"manifest"`
	ManifestHash  string         `json:"manifest_hash"`
	SignatureRefs []string       `json:"signature_refs"`
	CreatedAt     time.Time      `json:"created_at"`
	PublishedAt   *time.Time     `json:"published_at,omitempty"`
	RevokedAt     *time.Time     `json:"revoked_at,omitempty"`
}

type VerificationResult struct {
	ID          string        `json:"id"`
	TenantID    string        `json:"tenant_id"`
	SubjectType string        `json:"subject_type"`
	SubjectID   string        `json:"subject_id"`
	Result      string        `json:"result"`
	Checks      []VerifyCheck `json:"checks"`
	VerifiedAt  time.Time     `json:"verified_at"`
}

type VerifyCheck struct {
	Name   string `json:"name"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

type ReleaseReadinessReport struct {
	ReportType         string            `json:"report_type"`
	TemplateVersion    string            `json:"template_version"`
	ReleaseID          string            `json:"release_id"`
	Result             string            `json:"result"`
	Checks             []PolicyCheck     `json:"checks"`
	BlockingFindings   []BlockingFinding `json:"blocking_findings,omitempty"`
	AcceptedExceptions []Exception       `json:"accepted_exceptions,omitempty"`
	Gaps               []string          `json:"gaps,omitempty"`
	Assumptions        []string          `json:"assumptions"`
	Limitations        []string          `json:"limitations"`
	Metadata           map[string]any    `json:"metadata,omitempty"`
	GeneratedAt        time.Time         `json:"generated_at"`
}

type BlockingFinding struct {
	FindingID     string `json:"finding_id"`
	ScanID        string `json:"scan_id"`
	ReleaseID     string `json:"release_id,omitempty"`
	Vulnerability string `json:"vulnerability"`
	Component     string `json:"component,omitempty"`
	Severity      string `json:"severity"`
	State         string `json:"state"`
}

type DeploymentEnvironment struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ProductID     string    `json:"product_id"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
}

type DeploymentEvent struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	EnvironmentID string     `json:"environment_id"`
	ReleaseID     string     `json:"release_id"`
	ArtifactIDs   []string   `json:"artifact_ids,omitempty"`
	Status        string     `json:"status"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	RollbackOf    string     `json:"rollback_of,omitempty"`
	EvidenceID    string     `json:"evidence_id,omitempty"`
	SchemaVersion string     `json:"schema_version"`
	CreatedAt     time.Time  `json:"created_at"`
}

type Incident struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	ProductID     string     `json:"product_id"`
	ReleaseID     string     `json:"release_id,omitempty"`
	Title         string     `json:"title"`
	Severity      string     `json:"severity"`
	Status        string     `json:"status"`
	OpenedAt      time.Time  `json:"opened_at"`
	ClosedAt      *time.Time `json:"closed_at,omitempty"`
	SchemaVersion string     `json:"schema_version"`
	CreatedAt     time.Time  `json:"created_at"`
}

type IncidentTimelineEvent struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	IncidentID    string    `json:"incident_id"`
	EventType     string    `json:"event_type"`
	Summary       string    `json:"summary"`
	EvidenceID    string    `json:"evidence_id,omitempty"`
	OccurredAt    time.Time `json:"occurred_at"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
}

type RemediationTask struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	IncidentID    string     `json:"incident_id,omitempty"`
	ReleaseID     string     `json:"release_id,omitempty"`
	Title         string     `json:"title"`
	Owner         string     `json:"owner"`
	Status        string     `json:"status"`
	DueAt         *time.Time `json:"due_at,omitempty"`
	EvidenceID    string     `json:"evidence_id,omitempty"`
	SchemaVersion string     `json:"schema_version"`
	CreatedAt     time.Time  `json:"created_at"`
}

type IncidentReport struct {
	ReportType      string                  `json:"report_type"`
	TemplateVersion string                  `json:"template_version"`
	IncidentID      string                  `json:"incident_id"`
	Result          string                  `json:"result"`
	Timeline        []IncidentTimelineEvent `json:"timeline"`
	Tasks           []RemediationTask       `json:"tasks"`
	LinkedEvidence  []string                `json:"linked_evidence,omitempty"`
	Assumptions     []string                `json:"assumptions"`
	Limitations     []string                `json:"limitations"`
	GeneratedAt     time.Time               `json:"generated_at"`
}

type SecurityScan struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	ProductID     string         `json:"product_id,omitempty"`
	ReleaseID     string         `json:"release_id,omitempty"`
	ArtifactID    string         `json:"artifact_id,omitempty"`
	Category      string         `json:"category"`
	Format        string         `json:"format"`
	Scanner       string         `json:"scanner"`
	TargetRef     string         `json:"target_ref"`
	EvidenceID    string         `json:"evidence_id"`
	PayloadRef    string         `json:"payload_ref,omitempty"`
	PayloadHash   string         `json:"payload_hash"`
	FindingCount  int            `json:"finding_count"`
	Summary       map[string]int `json:"summary,omitempty"`
	Redacted      bool           `json:"redacted"`
	Quarantined   bool           `json:"quarantined"`
	SchemaVersion string         `json:"schema_version"`
	CreatedAt     time.Time      `json:"created_at"`
}

type ManualSecurityDocument struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ProductID     string    `json:"product_id,omitempty"`
	ReleaseID     string    `json:"release_id,omitempty"`
	DocumentType  string    `json:"document_type"`
	Title         string    `json:"title"`
	Sensitivity   string    `json:"sensitivity"`
	EvidenceID    string    `json:"evidence_id"`
	PayloadRef    string    `json:"payload_ref,omitempty"`
	PayloadHash   string    `json:"payload_hash"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
}

type SBOMDiff struct {
	ID                string             `json:"id"`
	TenantID          string             `json:"tenant_id"`
	BaseSBOMID        string             `json:"base_sbom_id"`
	TargetSBOMID      string             `json:"target_sbom_id"`
	ReleaseID         string             `json:"release_id,omitempty"`
	AddedComponents   []SBOMComponent    `json:"added_components,omitempty"`
	RemovedComponents []SBOMComponent    `json:"removed_components,omitempty"`
	UnchangedCount    int                `json:"unchanged_count"`
	DependencyChanges []DependencyChange `json:"dependency_changes,omitempty"`
	SchemaVersion     string             `json:"schema_version"`
	CreatedAt         time.Time          `json:"created_at"`
}

type DependencyChange struct {
	ID            string        `json:"id"`
	TenantID      string        `json:"tenant_id"`
	SBOMDiffID    string        `json:"sbom_diff_id"`
	ChangeType    string        `json:"change_type"`
	Component     SBOMComponent `json:"component"`
	SchemaVersion string        `json:"schema_version"`
	CreatedAt     time.Time     `json:"created_at"`
}

type VulnerabilityWorkflowRecord struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	FindingID     string    `json:"finding_id"`
	ReleaseID     string    `json:"release_id,omitempty"`
	Action        string    `json:"action"`
	Reason        string    `json:"reason"`
	ActorID       string    `json:"actor_id"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
}

type VulnerabilityPostureReport struct {
	ReportType      string         `json:"report_type"`
	TemplateVersion string         `json:"template_version"`
	ReleaseID       string         `json:"release_id,omitempty"`
	Summary         map[string]int `json:"summary"`
	OpenCritical    int            `json:"open_critical"`
	Assumptions     []string       `json:"assumptions"`
	Limitations     []string       `json:"limitations"`
	GeneratedAt     time.Time      `json:"generated_at"`
}

type ContractDiff struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	BaseContractID     string    `json:"base_contract_id"`
	TargetContractID   string    `json:"target_contract_id"`
	ProductID          string    `json:"product_id"`
	ReleaseID          string    `json:"release_id,omitempty"`
	Result             string    `json:"result"`
	BreakingChanges    []string  `json:"breaking_changes,omitempty"`
	NonBreakingChanges []string  `json:"non_breaking_changes,omitempty"`
	SchemaVersion      string    `json:"schema_version"`
	CreatedAt          time.Time `json:"created_at"`
}

type CustomPolicy struct {
	ID            string       `json:"id"`
	TenantID      string       `json:"tenant_id"`
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	Description   string       `json:"description,omitempty"`
	Rules         []PolicyRule `json:"rules"`
	SchemaVersion string       `json:"schema_version"`
	CreatedAt     time.Time    `json:"created_at"`
}

type PolicyRule struct {
	Name         string `json:"name"`
	EvidenceType string `json:"evidence_type,omitempty"`
	Severity     string `json:"severity"`
	Required     bool   `json:"required"`
}

type CustomPolicyEvaluation struct {
	ID            string        `json:"id"`
	TenantID      string        `json:"tenant_id"`
	PolicyID      string        `json:"policy_id"`
	ReleaseID     string        `json:"release_id"`
	Result        string        `json:"result"`
	Checks        []PolicyCheck `json:"checks"`
	InputHash     string        `json:"input_hash"`
	SchemaVersion string        `json:"schema_version"`
	CreatedAt     time.Time     `json:"created_at"`
}
