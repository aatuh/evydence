// Package domain owns identity and access models and authorization values.
package domain

import "time"

type APIKey struct {
	ID         string
	TenantID   string
	Name       string
	Prefix     string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
	Hash       string
}
type Actor struct {
	TenantID       string
	KeyID          string
	UserID         string
	SessionID      string
	Name           string
	Scopes         []string
	CollectorID    string
	ResourceGrants []ResourceGrant
}
type HumanUser struct {
	ID             string
	TenantID       string
	OrganizationID string
	Email          string
	DisplayName    string
	Status         string
	DeactivatedAt  *time.Time
	SchemaVersion  string
	CreatedAt      time.Time
}
type Organization struct {
	ID            string
	TenantID      string
	Name          string
	Slug          string
	Status        string
	SchemaVersion string
	CreatedAt     time.Time
}
type ProviderVerification struct {
	ID            string
	TenantID      string
	ProviderType  string
	ProviderID    string
	Subject       string
	Result        string
	Checks        []VerificationCheck
	Profile       VerificationProfileSnapshot
	Limitations   []string
	SchemaVersion string
	CreatedAt     time.Time
}
type ResourceGrant struct {
	Role         string
	ResourceType string
	ResourceID   string
	Scopes       []string
}
type RoleBinding struct {
	ID            string
	TenantID      string
	SubjectType   string
	SubjectID     string
	Role          string
	ResourceType  string
	ResourceID    string
	SchemaVersion string
	CreatedAt     time.Time
}
type SSOProvider struct {
	ID                      string
	TenantID                string
	Name                    string
	Type                    string
	Issuer                  string
	ClientID                string
	GroupsClaim             string
	RoleMapping             map[string]string
	JWKS                    map[string]any
	SAMLSigningCertificates []string
	TrustMaterialUpdatedAt  *time.Time
	Status                  string
	SchemaVersion           string
	CreatedAt               time.Time
}
type SSOSession struct {
	ID            string
	TenantID      string
	UserID        string
	ProviderID    string
	Prefix        string
	Groups        []string
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	SchemaVersion string
	CreatedAt     time.Time
	Hash          string
}
type Tenant struct {
	ID        string
	Name      string
	CreatedAt time.Time
}
type UserIdentityLink struct {
	ID            string
	TenantID      string
	UserID        string
	ProviderID    string
	Subject       string
	Email         string
	Verified      bool
	SchemaVersion string
	CreatedAt     time.Time
}
type VerificationProfileSnapshot struct {
	ID                string
	Version           string
	RequiredChecks    []string
	TrustMaterial     []string
	IdentityPolicy    string
	TransparencyProof string
	PayloadScope      string
	PayloadDigest     string
	Limitations       []string
}
type VerificationCheck struct {
	Name   string
	Result string
	Detail string
}
