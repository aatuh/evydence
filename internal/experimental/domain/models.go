// Package domain quarantines explicitly experimental peripheral models.
package domain

import "time"

type AnomalyReport struct {
	ID            string
	TenantID      string
	SubjectType   string
	SubjectID     string
	Result        string
	Signals       []AnomalySignal
	Assumptions   []string
	Limitations   []string
	SchemaVersion string
	CreatedAt     time.Time
}
type AnomalySignal struct {
	Name     string
	Severity string
	Detail   string
}
type MarketplaceCollector struct {
	ID            string
	TenantID      string
	Name          string
	Provider      string
	Version       string
	Publisher     string
	ManifestHash  string
	SignatureID   string
	SBOMID        string
	ScanID        string
	State         string
	Limitations   []string
	SchemaVersion string
	CreatedAt     time.Time
}
type MarketplaceCollectorHealthReport struct {
	ReportType        string
	CollectorID       string
	Name              string
	Provider          string
	Version           string
	SupplyChainStatus string
	Checks            []VerificationCheck
	Collector         MarketplaceCollector
	Assumptions       []string
	Limitations       []string
	GeneratedAt       time.Time
}
type PublicTransparencyLog struct {
	ID            string
	TenantID      string
	Name          string
	Endpoint      string
	PublicKey     string
	State         string
	SchemaVersion string
	CreatedAt     time.Time
}
type PublicTransparencyLogEntry struct {
	ID                      string
	TenantID                string
	LogID                   string
	CheckpointID            string
	MerkleBatchID           string
	ExternalID              string
	EntryHash               string
	InclusionRootHash       string
	InclusionProofHash      string
	InclusionVerifiedAt     *time.Time
	VerificationChecks      []VerificationCheck
	VerificationLimitations []string
	State                   string
	SchemaVersion           string
	CreatedAt               time.Time
}
type SaaSEditionProfile struct {
	ID             string
	TenantID       string
	Name           string
	Region         string
	AdminTenantID  string
	IsolationModel string
	Status         string
	ConfigHash     string
	Limitations    []string
	SchemaVersion  string
	CreatedAt      time.Time
}
type VerificationCheck struct {
	Name   string
	Result string
	Detail string
}
