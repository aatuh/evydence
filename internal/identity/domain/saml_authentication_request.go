package domain

import (
	"encoding/hex"
	"strings"
	"time"
)

const SAMLProviderBindingSchemaVersion = "saml-provider-binding.v1.0.0"
const SAMLAuthenticationRequestSchemaVersion = "saml-authentication-request.v1.0.0"
const MaximumSAMLAuthenticationRequestLifetime = 5 * time.Minute
const MaximumSAMLAuthenticationRequestsPerProvider = 64
const SAMLNameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

// SAMLProviderBinding owns the SP recipient and NameID namespace separately
// from the provider's existing public trust record. Provider is a snapshot.
type SAMLProviderBinding struct {
	TenantID      string
	ProviderID    string
	Provider      SSOProvider
	Recipient     string
	NameIDFormat  string
	SchemaVersion string
	UpdatedAt     time.Time
}

// SAMLAuthenticationRequest contains short-lived operational state. The state
// secret is delivered once; only its hash is stored. ID is the AuthnRequest ID.
type SAMLAuthenticationRequest struct {
	ID               string
	TenantID         string
	ProviderID       string
	Delivery         string
	Issuer           string
	Audience         string
	Recipient        string
	NameIDFormat     string
	TrustFingerprint string
	StateHash        string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	ConsumedAt       *time.Time
	SchemaVersion    string
}

// SAMLAssertionUse is transient verified proof metadata. The durable replay
// marker stores the scoped assertion hash and its finite retention deadline.
type SAMLAssertionUse struct {
	AssertionHash string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

func ValidSAMLID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i, b := range []byte(value) {
		letter := b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
		digit := b >= '0' && b <= '9'
		if letter || b == '_' || i > 0 && (digit || b == '-' || b == '.') {
			continue
		}
		return false
	}
	return true
}

func NormalizeSAMLNameIDFormat(value string) (string, bool) {
	if value == "" {
		value = SAMLNameIDUnspecified
	}
	switch value {
	case SAMLNameIDUnspecified, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress":
		return value, true
	default:
		return "", false
	}
}

func finiteSAMLTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}

func (r SAMLAuthenticationRequest) PendingAt(now time.Time) bool {
	format, ok := NormalizeSAMLNameIDFormat(r.NameIDFormat)
	return ValidSAMLID(r.ID) && r.TenantID != "" && r.ProviderID != "" && r.Issuer != "" && r.Audience != "" && r.Recipient != "" && ok && format == r.NameIDFormat &&
		(r.Delivery == "api" || r.Delivery == "browser") && r.SchemaVersion == SAMLAuthenticationRequestSchemaVersion && r.ConsumedAt == nil &&
		finiteSAMLTime(now) && finiteSAMLTime(r.CreatedAt) && finiteSAMLTime(r.ExpiresAt) && !now.Before(r.CreatedAt) && r.ExpiresAt.After(now) && !r.ExpiresAt.After(r.CreatedAt.Add(MaximumSAMLAuthenticationRequestLifetime))
}

func (p SAMLAssertionUse) ValidAt(now time.Time) bool {
	if len(p.AssertionHash) != 71 || !strings.HasPrefix(p.AssertionHash, "sha256:") || p.AssertionHash != strings.ToLower(p.AssertionHash) {
		return false
	}
	if hash, err := hex.DecodeString(p.AssertionHash[7:]); err != nil || len(hash) != 32 {
		return false
	}
	return finiteSAMLTime(now) && finiteSAMLTime(p.IssuedAt) && finiteSAMLTime(p.ExpiresAt) && !p.IssuedAt.After(now.Add(time.Minute)) &&
		p.ExpiresAt.After(now) && p.ExpiresAt.After(p.IssuedAt) && !p.ExpiresAt.After(p.IssuedAt.Add(MaximumSAMLAuthenticationRequestLifetime))
}
