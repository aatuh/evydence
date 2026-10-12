// Package domain owns accepted evidence models and subject references.
package domain

import "time"

type ContractDiff struct {
	ID                 string
	TenantID           string
	BaseContractID     string
	TargetContractID   string
	ProductID          string
	ReleaseID          string
	Result             string
	BreakingChanges    []string
	NonBreakingChanges []string
	SchemaVersion      string
	CreatedAt          time.Time
}
type DependencyChange struct {
	ID            string
	TenantID      string
	SBOMDiffID    string
	ChangeType    string
	Component     SBOMComponent
	SchemaVersion string
	CreatedAt     time.Time
}
type EvidenceItem struct {
	ID                  string
	TenantID            string
	ProductID           string
	ProjectID           string
	ReleaseID           string
	BuildID             string
	DeploymentID        string
	Type                string
	Subtype             string
	Title               string
	SourceSystem        string
	SourceIdentity      map[string]any
	CollectorID         string
	UploadedBy          string
	ObservedAt          time.Time
	EvidenceVersion     int
	SchemaVersion       string
	PayloadRef          string
	PayloadHash         string
	PayloadMediaType    string
	PayloadSize         int64
	CanonicalHash       string
	Canonicalization    string
	SubjectRefs         []SubjectRef
	RelatedEvidenceRefs []EvidenceRef
	Supersedes          string
	SupersededBy        string
	TrustLevel          string
	VerificationStatus  string
	SignatureRefs       []string
	ChainEntryID        string
	Tags                []string
	Metadata            map[string]any
	Warnings            []EvidenceNotice
	Limitations         []string
	CreatedAt           time.Time
}
type EvidenceLifecycleEvent struct {
	ID            string
	TenantID      string
	EvidenceID    string
	Action        EvidenceLifecycleState
	Reason        string
	Details       map[string]any
	ReplacementID string
	ActorID       string
	SchemaVersion string
	CreatedAt     time.Time
}
type EvidenceNotice struct {
	Code    string
	Message string
}
type EvidenceRef struct {
	Type         string
	ID           string
	Relationship string
}
type ManualSecurityDocument struct {
	ID            string
	TenantID      string
	ProductID     string
	ReleaseID     string
	DocumentType  string
	Title         string
	Sensitivity   string
	EvidenceID    string
	PayloadRef    string
	PayloadHash   string
	SchemaVersion string
	CreatedAt     time.Time
}
type OpenAPIContract struct {
	ID         string
	TenantID   string
	ProductID  string
	ReleaseID  string
	Version    string
	Hash       string
	PathCount  int
	Operations []OpenAPIOperation
	EvidenceID string
	CreatedAt  time.Time
}
type OpenAPIOperation struct {
	Path                  string
	Method                string
	OperationID           string
	Deprecated            bool
	RequestBodyRequired   bool
	RequiredRequestFields []string
	ResponseStatuses      []string
}
type SBOM struct {
	ID             string
	TenantID       string
	EvidenceID     string
	ReleaseID      string
	ArtifactID     string
	Format         string
	SpecVersion    string
	ComponentCount int
	Components     []SBOMComponent
	CreatedAt      time.Time
}
type SBOMComponent struct {
	Identity string
	Name     string
	Version  string
	PURL     string
}
type SBOMComponentRecord struct {
	ID          string
	SBOMID      string
	ReleaseID   string
	ArtifactID  string
	Format      string
	SpecVersion string
	Component   SBOMComponent
}
type SBOMDiff struct {
	ID                string
	TenantID          string
	BaseSBOMID        string
	TargetSBOMID      string
	ReleaseID         string
	AddedComponents   []SBOMComponent
	RemovedComponents []SBOMComponent
	UnchangedCount    int
	DependencyChanges []DependencyChange
	SchemaVersion     string
	CreatedAt         time.Time
}
type SecurityScan struct {
	ID            string
	TenantID      string
	ProductID     string
	ReleaseID     string
	ArtifactID    string
	Category      string
	Format        string
	Scanner       string
	TargetRef     string
	EvidenceID    string
	PayloadRef    string
	PayloadHash   string
	FindingCount  int
	Summary       map[string]int
	Redacted      bool
	Quarantined   bool
	SchemaVersion string
	CreatedAt     time.Time
}
type SubjectRef struct {
	Type   string
	ID     string
	Digest string
}
type VEXDocument struct {
	ID             string
	TenantID       string
	EvidenceID     string
	ReleaseID      string
	ArtifactID     string
	Format         string
	Author         string
	Version        string
	StatementCount int
	StatusSummary  map[string]int
	SchemaVersion  string
	CreatedAt      time.Time
}
type VEXImportIssue struct {
	StatementIndex int
	Code           string
	Detail         string
}
type VEXImportPreview struct {
	TenantID                string
	ReleaseID               string
	ArtifactID              string
	Format                  string
	ParserVersion           string
	Advisory                bool
	StatementCount          int
	StatusSummary           map[string]int
	DecisionsWouldCreate    int
	DecisionsWouldSupersede int
	Warnings                []string
	InvalidStatements       []VEXImportIssue
	MappingFailures         []VEXImportIssue
	Assumptions             []string
	Limitations             []string
	SchemaVersion           string
	GeneratedAt             time.Time
}
type VEXImportReport struct {
	ID                  string
	TenantID            string
	VEXDocumentID       string
	EvidenceID          string
	ReleaseID           string
	ArtifactID          string
	ParserVersion       string
	Status              string
	StatementCount      int
	DecisionsCreated    int
	DecisionsSuperseded int
	UnsupportedFields   []string
	Warnings            []string
	InvalidStatements   []VEXImportIssue
	MappingFailures     []VEXImportIssue
	FailureCode         string
	FailureDetail       string
	SchemaVersion       string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}
type VulnerabilityFinding struct {
	ID             string
	Vulnerability  string
	Component      string
	Severity       string
	State          string
	SeveritySource string
	FixVersion     string
	Identity       VulnerabilityIdentity
}
type VulnerabilityIdentity struct {
	CVE            string
	GHSA           string
	OSV            string
	VendorAdvisory string
	PURL           string
	CPE            string
}
type VulnerabilityScan struct {
	ID             string
	TenantID       string
	EvidenceID     string
	ReleaseID      string
	Scanner        string
	Adapter        string
	AdapterVersion string
	SourceSchema   string
	TargetRef      string
	Summary        map[string]int
	Findings       []VulnerabilityFinding
	CreatedAt      time.Time
}
