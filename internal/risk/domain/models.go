// Package domain owns vulnerability decisions and governance models.
package domain

import "time"

type ApprovalRecord struct {
	ID            string
	TenantID      string
	SubjectType   string
	SubjectID     string
	Decision      string
	Reason        string
	ApproverID    string
	EvidenceID    string
	SchemaVersion string
	CreatedAt     time.Time
}
type ControlEvidence struct {
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
type ControlEvidenceRequirement struct {
	Type          string
	FreshnessDays int
	Required      bool
}
type ControlFramework struct {
	ID            string
	TenantID      string
	Name          string
	Slug          string
	Version       string
	Description   string
	Status        string
	SchemaVersion string
	CreatedAt     time.Time
}
type ControlFrameworkTemplatePack struct {
	ID            string
	Name          string
	Slug          string
	Version       string
	Description   string
	Controls      []SecurityControl
	SchemaVersion string
}
type CustomPolicy struct {
	ID            string
	TenantID      string
	Name          string
	Version       string
	Description   string
	Rules         []PolicyRule
	SchemaVersion string
	CreatedAt     time.Time
}
type CustomPolicyEvaluation struct {
	ID            string
	TenantID      string
	PolicyID      string
	ReleaseID     string
	Result        string
	Checks        []PolicyCheck
	InputHash     string
	SchemaVersion string
	CreatedAt     time.Time
}
type Exception struct {
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
type PolicyCheck struct {
	Name        string
	Result      string
	Severity    string
	Missing     []string
	Explanation string
	Remediation string
}
type PolicyEvaluation struct {
	ID        string
	TenantID  string
	ReleaseID string
	Result    string
	PolicySet string
	Checks    []PolicyCheck
	CreatedAt time.Time
}
type PolicyRule struct {
	Name         string
	EvidenceType string
	Severity     string
	Required     bool
}
type ReleaseSecurityApprovalSummary struct {
	Total    int
	Approved int
}
type ReleaseSecurityExceptionSummary struct {
	Total             int
	ApprovedUnexpired int
	Unapproved        int
	Expired           int
}
type ReleaseSecurityMissingDecision struct {
	FindingID     string
	ScanID        string
	Vulnerability string
	Component     string
	Severity      string
	State         string
}
type ReleaseSecurityProductSummary struct {
	ID   string
	Name string
	Slug string
}
type ReleaseSecurityReleaseSummary struct {
	ID      string
	Version string
	State   string
}
type ReleaseSecuritySummary struct {
	Product                  ReleaseSecurityProductSummary
	Release                  ReleaseSecurityReleaseSummary
	ArtifactCount            int
	SBOMStatus               string
	VulnerabilityScanStatus  string
	OpenFindingsBySeverity   map[string]int
	DecisionsByStatus        map[string]int
	MissingRequiredDecisions []ReleaseSecurityMissingDecision
	ApprovalSummary          ReleaseSecurityApprovalSummary
	ExceptionSummary         ReleaseSecurityExceptionSummary
	ReadinessStatus          string
	PackageStatus            string
	Counts                   map[string]int
	Assumptions              []string
	Limitations              []string
	SchemaVersion            string
	GeneratedAt              time.Time
}
type SecurityControl struct {
	ID                   string
	TenantID             string
	FrameworkID          string
	Code                 string
	Title                string
	Objective            string
	EvidenceRequirements []ControlEvidenceRequirement
	Applicability        []string
	Limitations          []string
	SchemaVersion        string
	CreatedAt            time.Time
}
type VulnerabilityDecision struct {
	ID                string
	TenantID          string
	FindingID         string
	ScanID            string
	ReleaseID         string
	Vulnerability     string
	Component         string
	SBOMID            string
	SBOMComponentPURL string
	SBOMComponentName string
	Status            DecisionStatus
	Justification     string
	ImpactStatement   string
	ActionStatement   string
	CustomerVisible   bool
	InternalNotes     string
	Source            string
	EvidenceID        string
	EvidenceIDs       []string
	SupportingRefs    []SupportingReference
	VEXDocumentID     string
	Supersedes        string
	SupersededBy      string
	ApprovedBy        string
	ReviewedAt        *time.Time
	ReviewDueAt       *time.Time
	SchemaVersion     string
	CreatedAt         time.Time
}
type VulnerabilityDecisionCustomerSummary struct {
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
type VulnerabilityDecisionSummaryReport struct {
	ReportType      string
	TemplateVersion string
	ProductID       string
	ReleaseID       string
	Decisions       []VulnerabilityDecisionCustomerSummary
	Assumptions     []string
	Limitations     []string
	GeneratedAt     time.Time
}
type VulnerabilityWorkflowRecord struct {
	ID            string
	TenantID      string
	FindingID     string
	ReleaseID     string
	Action        string
	Reason        string
	ActorID       string
	SchemaVersion string
	CreatedAt     time.Time
}
type Waiver struct {
	ID            string
	TenantID      string
	ScopeType     string
	ScopeID       string
	ControlID     string
	PolicyID      string
	Owner         string
	Risk          string
	Reason        string
	ExpiresAt     time.Time
	Approved      bool
	ApprovedBy    string
	ApprovedAt    *time.Time
	Supersedes    string
	SupersededBy  string
	SchemaVersion string
	CreatedAt     time.Time
}
type SupportingReference struct {
	Type   string
	ID     string
	Digest string
}
