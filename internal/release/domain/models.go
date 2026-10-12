// Package domain owns release catalog models and lifecycle rules.
package domain

import "time"

type Artifact struct {
	ID        string
	TenantID  string
	Name      string
	MediaType string
	Size      int64
	Digest    string
	CreatedAt time.Time
}
type BuildAttestation struct {
	ID                 string
	TenantID           string
	BuildID            string
	EvidenceID         string
	PayloadRef         string
	PayloadHash        string
	PayloadSize        int64
	PayloadType        string
	PredicateType      string
	SubjectDigests     []string
	BuilderID          string
	BuildType          string
	MaterialsCount     int
	SignatureCount     int
	VerificationStatus string
	SchemaVersion      string
	CreatedAt          time.Time
}
type BuildOutput struct {
	ArtifactID string
	Digest     string
}
type BuildRun struct {
	ID              string
	TenantID        string
	ProjectID       string
	ReleaseID       string
	CollectorID     string
	Provider        string
	CommitSHA       string
	Repository      string
	WorkflowRef     string
	RunID           string
	RunAttempt      int
	JobID           string
	Actor           string
	Ref             string
	OIDCSubject     string
	Status          string
	StartedAt       time.Time
	FinishedAt      *time.Time
	ParametersHash  string
	EnvironmentHash string
	SourceIdentity  map[string]any
	Outputs         []BuildOutput
	SchemaVersion   string
	CreatedAt       time.Time
}
type ContainerImage struct {
	ID            string
	TenantID      string
	ArtifactID    string
	Repository    string
	Tag           string
	Digest        string
	Platform      string
	SchemaVersion string
	CreatedAt     time.Time
}
type Product struct {
	ID        string
	TenantID  string
	Name      string
	Slug      string
	CreatedAt time.Time
}
type Project struct {
	ID        string
	TenantID  string
	ProductID string
	Name      string
	CreatedAt time.Time
}
type Release struct {
	ID         string
	TenantID   string
	ProductID  string
	Version    string
	Revision   int64
	State      ReleaseState
	CreatedAt  time.Time
	FrozenAt   *time.Time
	ApprovedAt *time.Time
}
type ReleaseCandidate struct {
	ID            string
	TenantID      string
	ReleaseID     string
	Name          string
	Revision      int64
	State         ReleaseCandidateState
	BuildIDs      []string
	ArtifactIDs   []string
	SBOMIDs       []string
	ScanIDs       []string
	VEXIDs        []string
	ContractIDs   []string
	BundleIDs     []string
	SnapshotHash  string
	SchemaVersion string
	CreatedAt     time.Time
	PromotedAt    *time.Time
	RejectedAt    *time.Time
}
type ReleaseEvidenceFlow struct {
	ReleaseID     string
	ProductID     string
	Status        string
	Counts        map[string]int
	Steps         []ReleaseEvidenceFlowStep
	Assumptions   []string
	Limitations   []string
	SchemaVersion string
	GeneratedAt   time.Time
}
type ReleaseEvidenceFlowStep struct {
	ID                  string
	Title               string
	Status              string
	Required            bool
	Method              string
	Path                string
	RequiredScopes      []string
	IdempotencyRequired bool
	Description         string
	NextReference       string
}
