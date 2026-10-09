// Package domain owns collector and source-integration models.
package domain

import "time"

type Collector struct {
	ID            string
	TenantID      string
	Name          string
	Type          string
	Version       string
	APIKeyID      string
	Status        CollectorStatus
	AllowedScopes []string
	LastSeenAt    *time.Time
	SchemaVersion string
	CreatedAt     time.Time
}
type CollectorHealthReport struct {
	ReportType        string
	CollectorID       string
	CollectorStatus   string
	Version           string
	PinnedReleaseID   string
	SupplyChainStatus string
	Checks            []VerificationCheck
	LatestRelease     *CollectorRelease
	Assumptions       []string
	Limitations       []string
	GeneratedAt       time.Time
}
type CollectorRelease struct {
	ID                 string
	TenantID           string
	CollectorID        string
	Version            string
	ArtifactDigest     string
	SignatureID        string
	SBOMID             string
	ScanID             string
	Pinned             bool
	VerificationStatus string
	HealthStatus       string
	Limitations        []string
	SchemaVersion      string
	CreatedAt          time.Time
}
type CommercialCollectorDefinition struct {
	ID            string
	TenantID      string
	Name          string
	Provider      string
	Version       string
	ManifestHash  string
	AllowedScopes []string
	Status        string
	SchemaVersion string
	CreatedAt     time.Time
}
type PullRequest struct {
	ID             string
	TenantID       string
	RepositoryID   string
	Provider       string
	ProviderID     string
	Title          string
	State          string
	SourceBranch   string
	TargetBranch   string
	HeadCommitID   string
	ReviewDecision string
	SchemaVersion  string
	CreatedAt      time.Time
}
type SourceBranch struct {
	ID             string
	TenantID       string
	RepositoryID   string
	Name           string
	HeadCommitID   string
	Protected      bool
	ProtectionHash string
	SchemaVersion  string
	CreatedAt      time.Time
}
type SourceCommit struct {
	ID            string
	TenantID      string
	RepositoryID  string
	SHA           string
	Author        string
	MessageHash   string
	CommittedAt   time.Time
	SchemaVersion string
	CreatedAt     time.Time
}
type SourceRepository struct {
	ID            string
	TenantID      string
	ProjectID     string
	Provider      string
	FullName      string
	CloneURL      string
	DefaultBranch string
	SchemaVersion string
	CreatedAt     time.Time
}
type VerificationCheck struct {
	Name   string
	Result string
	Detail string
}
