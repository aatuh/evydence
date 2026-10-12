// Package domain owns customer package, bundle, and report models.
package domain

import "time"

type BlockingFinding struct {
	FindingID     string
	ScanID        string
	ReleaseID     string
	Vulnerability string
	Component     string
	Severity      string
	State         string
}
type CRAReadinessReport struct {
	ReportType         string
	TemplateVersion    string
	ProductID          string
	ReleaseID          string
	Result             string
	Controls           []ControlCoverageItem
	MissingEvidence    []string
	AcceptedExceptions []AcceptedExceptionSnapshot
	Assumptions        []string
	Limitations        []string
	GeneratedAt        time.Time
}
type CRAVulnerabilityHandlingReport struct {
	ReportType         string
	TemplateVersion    string
	ProductID          string
	ReleaseID          string
	Summary            map[string]int
	Decisions          []VulnerabilityDecisionSnapshot
	AcceptedExceptions []AcceptedExceptionSnapshot
	EvidenceIDs        []string
	Assumptions        []string
	Limitations        []string
	GeneratedAt        time.Time
}
type ControlCoverageItem struct {
	ControlID      string
	Code           string
	Title          string
	Status         string
	Confidence     string
	LinkedEvidence []ControlEvidenceSnapshot
	Missing        []string
	Explanation    string
	Limitations    []string
}
type ControlCoverageReport struct {
	ReportType         string
	TemplateVersion    string
	FrameworkID        string
	ProductID          string
	ReleaseID          string
	Result             string
	Controls           []ControlCoverageItem
	MissingEvidence    []string
	AcceptedExceptions []AcceptedExceptionSnapshot
	Assumptions        []string
	Limitations        []string
	GeneratedAt        time.Time
}
type CustomReportTemplate struct {
	ID            string
	TenantID      string
	Name          string
	Version       string
	ReportType    string
	AllowedFields []string
	Template      string
	SchemaVersion string
	CreatedAt     time.Time
}
type CustomerPortalAccess struct {
	ID                string
	TenantID          string
	PackageID         string
	CustomerName      string
	ReviewerName      string
	ReviewerEmail     string
	RequireNDA        bool
	NDAAcceptedAt     *time.Time
	NDAAcceptedBy     string
	Watermark         string
	Prefix            string
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	AccessCount       int
	FailedAccessCount int
	LastAccessedAt    *time.Time
	LastFailedAt      *time.Time
	SchemaVersion     string
	CreatedAt         time.Time
	Hash              string
}
type CustomerSecurityPackage struct {
	ID                    string
	TenantID              string
	ProductID             string
	ReleaseID             string
	RedactionProfileID    string
	Title                 string
	State                 string
	Manifest              map[string]any
	ManifestHash          string
	DistributionWatermark string
	ExpiresAt             time.Time
	AccessCount           int
	SchemaVersion         string
	CreatedAt             time.Time
}
type EvidenceBundle struct {
	ID               string
	TenantID         string
	ReleaseID        string
	EvidenceIDs      []string
	Manifest         map[string]any
	ManifestHash     string
	SignatureRefs    []string
	VerificationText string
	SchemaVersion    string
	CreatedAt        time.Time
}
type EvidenceBundleImport struct {
	ID            string
	TenantID      string
	BundleHash    string
	Result        string
	ImportedCount int
	SchemaVersion string
	CreatedAt     time.Time
}
type EvidenceCitation struct {
	EvidenceID    string
	Type          string
	Title         string
	CanonicalHash string
}
type EvidenceGraphSnapshot struct {
	ID            string
	TenantID      string
	ProductID     string
	ReleaseID     string
	Nodes         []GraphNode
	Edges         []GraphEdge
	GraphHash     string
	Limitations   []string
	SchemaVersion string
	CreatedAt     time.Time
}
type EvidenceSummary struct {
	ID            string
	TenantID      string
	SubjectType   string
	SubjectID     string
	EvidenceIDs   []string
	Summary       string
	Citations     []EvidenceCitation
	Assumptions   []string
	Limitations   []string
	SchemaVersion string
	CreatedAt     time.Time
}
type GraphEdge struct {
	From         string
	To           string
	Relationship string
}
type GraphNode struct {
	ID    string
	Type  string
	Label string
}
type HTMLReportPackage struct {
	ID            string
	TenantID      string
	ReportType    string
	ProductID     string
	ReleaseID     string
	HTML          string
	Hash          string
	SchemaVersion string
	CreatedAt     time.Time
}
type IncidentReport struct {
	ReportType      string
	TemplateVersion string
	IncidentID      string
	Result          string
	Timeline        []IncidentTimelineEventSnapshot
	Tasks           []RemediationTaskSnapshot
	LinkedEvidence  []string
	Assumptions     []string
	Limitations     []string
	GeneratedAt     time.Time
}
type PDFReportPackage struct {
	ID            string
	TenantID      string
	ReportType    string
	ProductID     string
	ReleaseID     string
	Title         string
	PayloadRef    string
	PayloadHash   string
	PayloadSize   int64
	Limitations   []string
	SchemaVersion string
	CreatedAt     time.Time
}
type QuestionnaireAnswerLibraryEntry struct {
	ID            string
	TenantID      string
	QuestionID    string
	EvidenceType  string
	ControlID     string
	ProductID     string
	ReleaseID     string
	Answer        string
	EvidenceIDs   []string
	Limitations   []string
	SchemaVersion string
	CreatedAt     time.Time
}
type QuestionnaireDraft struct {
	ID            string
	TenantID      string
	TemplateID    string
	ProductID     string
	ReleaseID     string
	Responses     []QuestionnaireResponse
	ManifestHash  string
	Limitations   []string
	SchemaVersion string
	CreatedAt     time.Time
}
type QuestionnairePackage struct {
	ID            string
	TenantID      string
	TemplateID    string
	PackageID     string
	ProductID     string
	ReleaseID     string
	Responses     []QuestionnaireResponse
	ManifestHash  string
	SchemaVersion string
	CreatedAt     time.Time
}
type QuestionnaireQuestion struct {
	ID            string
	Prompt        string
	EvidenceType  string
	ControlID     string
	AllowedFields []string
}
type QuestionnaireResponse struct {
	QuestionID  string
	Answer      string
	EvidenceIDs []string
	Limitations []string
}
type QuestionnaireTemplate struct {
	ID            string
	TenantID      string
	Name          string
	Version       string
	Questions     []QuestionnaireQuestion
	SchemaVersion string
	CreatedAt     time.Time
}
type ReadinessQuestion struct {
	ID               string
	Question         string
	Answer           string
	Status           string
	Evidence         []string
	Checks           []string
	MissingEvidence  []string
	FailedPolicies   []string
	KnownLimitations []string
}
type ReadinessSection struct {
	ID        string
	Title     string
	Status    string
	Summary   string
	Questions []ReadinessQuestion
}
type ReadinessSummary struct {
	Headline     string
	Result       string
	HumanSummary string
	PolicySet    string
}
type RedactionProfile struct {
	ID             string
	TenantID       string
	Name           string
	Description    string
	AllowedTypes   []string
	ExcludedFields []string
	SchemaVersion  string
	CreatedAt      time.Time
}
type ReleaseBundle struct {
	ID            string
	TenantID      string
	ReleaseID     string
	State         BundleState
	Manifest      map[string]any
	ManifestHash  string
	SignatureRefs []string
	CreatedAt     time.Time
	PublishedAt   *time.Time
	RevokedAt     *time.Time
}
type ReleaseReadinessReport struct {
	ReportType         string
	TemplateVersion    string
	ReleaseID          string
	Result             string
	PolicySet          string
	Summary            ReadinessSummary
	Checks             []PolicyCheckSnapshot
	Sections           []ReadinessSection
	BlockingFindings   []BlockingFinding
	AcceptedExceptions []AcceptedExceptionSnapshot
	Gaps               []string
	MissingEvidence    []string
	FailedPolicies     []string
	KnownLimitations   []string
	NonClaims          []string
	Assumptions        []string
	Limitations        []string
	Metadata           map[string]any
	GeneratedAt        time.Time
}
type RenderedCustomReport struct {
	ID            string
	TenantID      string
	TemplateID    string
	SubjectType   string
	SubjectID     string
	Output        map[string]any
	Hash          string
	SchemaVersion string
	CreatedAt     time.Time
}
type SecurityReviewPackageReport struct {
	ReportType      string
	TemplateVersion string
	PackageID       string
	ProductID       string
	ReleaseID       string
	EvidenceIDs     []string
	Assumptions     []string
	Limitations     []string
	GeneratedAt     time.Time
}
type SecurityUpdateEvidenceReport struct {
	ReportType       string
	TemplateVersion  string
	ProductID        string
	ReleaseID        string
	Summary          map[string]int
	FixedDecisions   []VulnerabilityDecisionSnapshot
	Incidents        []IncidentSnapshot
	RemediationTasks []RemediationTaskSnapshot
	EvidenceIDs      []string
	Assumptions      []string
	Limitations      []string
	GeneratedAt      time.Time
}
type VulnerabilityPostureReport struct {
	ReportType      string
	TemplateVersion string
	ReleaseID       string
	Summary         map[string]int
	OpenCritical    int
	Assumptions     []string
	Limitations     []string
	GeneratedAt     time.Time
}
type SupportingReference struct {
	Type   string
	ID     string
	Digest string
}
type AcceptedExceptionSnapshot struct {
	ID         string
	TenantID   string
	ReleaseID  string
	FindingID  string
	ControlID  string
	Reason     string
	Owner      string
	ExpiresAt  time.Time
	Approved   bool
	ApprovedBy string
	ApprovedAt *time.Time
	CreatedAt  time.Time
}
type VulnerabilityDecisionSnapshot struct {
	ID                string
	FindingID         string
	ScanID            string
	ReleaseID         string
	Vulnerability     string
	Component         string
	SBOMID            string
	SBOMComponentPURL string
	SBOMComponentName string
	Status            string
	Justification     string
	ImpactStatement   string
	ActionStatement   string
	Source            string
	EvidenceID        string
	EvidenceIDs       []string
	SupportingRefs    []SupportingReference
	VEXDocumentID     string
	ReviewedAt        *time.Time
	ReviewDueAt       *time.Time
	CreatedAt         time.Time
}
type IncidentSnapshot struct {
	ID            string
	TenantID      string
	ProductID     string
	ReleaseID     string
	Title         string
	Severity      string
	Status        string
	OpenedAt      time.Time
	ClosedAt      *time.Time
	SchemaVersion string
	CreatedAt     time.Time
}
type RemediationTaskSnapshot struct {
	ID            string
	TenantID      string
	IncidentID    string
	ReleaseID     string
	Title         string
	Owner         string
	Status        string
	DueAt         *time.Time
	EvidenceID    string
	SchemaVersion string
	CreatedAt     time.Time
}
type ControlEvidenceSnapshot struct {
	ID            string
	TenantID      string
	ControlID     string
	EvidenceType  string
	SubjectType   string
	SubjectID     string
	ProductID     string
	ReleaseID     string
	Confidence    string
	Notes         string
	SchemaVersion string
	CreatedAt     time.Time
}
type IncidentTimelineEventSnapshot struct {
	ID            string
	TenantID      string
	IncidentID    string
	EventType     string
	Summary       string
	EvidenceID    string
	OccurredAt    time.Time
	SchemaVersion string
	CreatedAt     time.Time
}
type PolicyCheckSnapshot struct {
	Name        string
	Result      string
	Severity    string
	Missing     []string
	Explanation string
	Remediation string
}
