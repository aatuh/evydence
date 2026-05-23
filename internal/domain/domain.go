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
)

type Actor struct {
	TenantID string
	KeyID    string
	Name     string
	Scopes   []string
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
