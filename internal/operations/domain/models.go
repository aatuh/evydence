// Package domain owns incident, retention, deployment, and platform-operation models.
package domain

import "time"

type DeploymentEnvironment struct {
	ID            string
	TenantID      string
	ProductID     string
	Name          string
	Kind          string
	SchemaVersion string
	CreatedAt     time.Time
}
type DeploymentEvent struct {
	ID            string
	TenantID      string
	EnvironmentID string
	ReleaseID     string
	ArtifactIDs   []string
	Status        string
	StartedAt     time.Time
	FinishedAt    *time.Time
	RollbackOf    string
	EvidenceID    string
	SchemaVersion string
	CreatedAt     time.Time
}
type Incident struct {
	ID            string
	TenantID      string
	ProductID     string
	ReleaseID     string
	Title         string
	Severity      string
	Status        IncidentStatus
	OpenedAt      time.Time
	ClosedAt      *time.Time
	SchemaVersion string
	CreatedAt     time.Time
}
type IncidentTimelineEvent struct {
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
type IncidentWebhookEvent struct {
	ID              string
	TenantID        string
	ReceiverID      string
	IncidentID      string
	Provider        string
	EventID         string
	PayloadHash     string
	SignatureHash   string
	TimelineEventID string
	Result          string
	SchemaVersion   string
	CreatedAt       time.Time
}
type IncidentWebhookReceiver struct {
	ID            string
	TenantID      string
	IncidentID    string
	Name          string
	Provider      string
	PublicKey     string
	Status        string
	SchemaVersion string
	CreatedAt     time.Time
}
type InstanceAdminSnapshot struct {
	ReportType     string
	TenantCount    int
	ResourceCounts map[string]int
	Limitations    []string
	GeneratedAt    time.Time
}
type LegalHold struct {
	ID            string
	TenantID      string
	ScopeType     string
	ScopeID       string
	Reason        string
	Owner         string
	ReleasedAt    *time.Time
	SchemaVersion string
	CreatedAt     time.Time
}
type RemediationTask struct {
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
type RetentionOverride struct {
	ID             string
	TenantID       string
	ScopeType      string
	ScopeID        string
	RetentionUntil time.Time
	Reason         string
	Owner          string
	SchemaVersion  string
	CreatedAt      time.Time
}
type RetentionReport struct {
	ReportType         string
	ScopeType          string
	ScopeID            string
	LegalHolds         []LegalHold
	RetentionOverrides []RetentionOverride
	Limitations        []string
	GeneratedAt        time.Time
}
