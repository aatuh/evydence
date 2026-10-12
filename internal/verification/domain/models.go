// Package domain owns verification receipts and signing metadata models.
package domain

import "time"

type ArtifactSignature struct {
	ID                 string
	TenantID           string
	ArtifactID         string
	SubjectDigest      string
	Algorithm          string
	KeyID              string
	Signature          string
	PayloadRef         string
	PayloadHash        string
	VerificationStatus string
	SchemaVersion      string
	CreatedAt          time.Time
}
type AuditChainEntry struct {
	ID                 string
	TenantID           string
	Sequence           int64
	EntryType          string
	SubjectType        string
	SubjectID          string
	ActorType          string
	ActorID            string
	OccurredAt         time.Time
	RequestID          string
	IdempotencyKey     string
	PayloadHash        string
	CanonicalEntryHash string
	PreviousEntryHash  string
	EntryHash          string
	SignatureRef       string
	Metadata           map[string]any
	SchemaVersion      string
}
type BackupManifest struct {
	ID                string
	TenantID          string
	StateHash         string
	ResourceCounts    map[string]int
	ConsistencyChecks []VerifyCheck
	Limitations       []string
	SchemaVersion     string
	CreatedAt         time.Time
}
type CosignVerification struct {
	ID                     string
	TenantID               string
	ArtifactID             string
	ContainerImageID       string
	ArtifactSignatureID    string
	SubjectDigest          string
	RekorUUID              string
	RekorLogIndex          string
	CertificateIdentity    string
	CertificateIssuer      string
	VerifierLibraryVersion string
	TrustRootVersion       string
	VerificationMode       string
	Result                 string
	Checks                 []VerifyCheck
	Profile                VerificationProfile
	Limitations            []string
	SchemaVersion          string
	CreatedAt              time.Time
}
type DSSETrustRoot struct {
	ID                    string
	TenantID              string
	Name                  string
	KeyID                 string
	Algorithm             string
	PublicKey             string
	AllowedPredicateTypes []string
	ExpectedBuilderIDs    []string
	RequiredClaims        []string
	Status                string
	SchemaVersion         string
	CreatedAt             time.Time
}
type MerkleBatch struct {
	ID            string
	TenantID      string
	FromSequence  int64
	ToSequence    int64
	EntryCount    int
	LeafHashes    []string
	RootHash      string
	SignatureRefs []string
	SchemaVersion string
	CreatedAt     time.Time
}
type ObjectRetentionPolicy struct {
	ID                        string
	TenantID                  string
	Name                      string
	ObjectPrefix              string
	ObjectKey                 string
	RequireLegalHold          bool
	Mode                      string
	RetentionDays             int
	MaxVerificationAgeHours   int
	Status                    string
	VerifiedAt                *time.Time
	VerificationHash          string
	VerificationChecks        []VerifyCheck
	VerificationLimitations   []string
	VerificationProvider      string
	VerificationBucket        string
	VerificationMode          string
	VerificationRetentionDays int
	VerificationLegalHold     *bool
	VerificationObservedAt    *time.Time
	VerificationExpiresAt     *time.Time
	SchemaVersion             string
	CreatedAt                 time.Time
}
type Signature struct {
	ID          string
	TenantID    string
	SubjectType string
	SubjectID   string
	KeyID       string
	Algorithm   string
	Value       string
	CreatedAt   time.Time
}
type SigningCustodyReviewReport struct {
	ReportType              string
	TenantID                string
	SigningProviders        []SigningProvider
	ObjectRetentionPolicies []ObjectRetentionPolicy
	Checks                  []VerifyCheck
	Assumptions             []string
	Limitations             []string
	GeneratedAt             time.Time
}
type SigningKey struct {
	ID                       string
	TenantID                 string
	KID                      string
	Version                  int
	Provider                 string
	Algorithm                string
	Status                   SigningKeyStatus
	PublicKey                string
	PublicKeyFingerprint     string
	ValidFrom                time.Time
	ValidUntil               *time.Time
	CreatedAt                time.Time
	RevokedAt                *time.Time
	RevocationReason         string
	RevocationSemantics      string
	HistoricalValidityPolicy string
	CompromisedAt            *time.Time
}
type SigningOperation struct {
	ID                   string
	TenantID             string
	ProviderID           string
	SubjectType          string
	SubjectID            string
	PayloadHash          string
	CanonicalPayloadHash string
	RequestID            string
	ProviderRequestID    string
	SignatureRef         string
	Result               string
	Checks               []VerifyCheck
	SchemaVersion        string
	CreatedAt            time.Time
}
type SigningProvider struct {
	ID            string
	TenantID      string
	Name          string
	Type          string
	Status        string
	KeyRef        string
	Encrypted     bool
	SchemaVersion string
	CreatedAt     time.Time
}
type TransparencyCheckpoint struct {
	ID            string
	TenantID      string
	BatchID       string
	Provider      string
	ExternalURL   string
	ExternalID    string
	TimestampHash string
	State         string
	SchemaVersion string
	CreatedAt     time.Time
}
type VerificationResult struct {
	ID            string
	TenantID      string
	SubjectType   string
	SubjectID     string
	Result        VerificationState
	Checks        []VerifyCheck
	Profile       VerificationProfile
	Limitations   []string
	SchemaVersion string
	VerifiedAt    time.Time
}
type VerifyCheck struct {
	Name   string
	Result string
	Detail string
}
type VerificationProfile struct {
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
type VerificationProfileDefinition struct {
	ID                 string
	Version            string
	RequiredChecks     []string
	OptionalChecks     []string
	Canonicalization   string
	HashAlgorithm      string
	SignatureAlgorithm string
	TrustRootPolicy    string
	IdentityPolicy     string
	IssuerPolicy       string
	TransparencyPolicy string
	ClockPolicy        string
	RevocationPolicy   string
	OfflinePolicy      string
}
