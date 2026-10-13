package domain

import "time"

const OIDCAuthenticationRequestSchemaVersion = "oidc-authentication-request.v1.0.0"
const MaximumOIDCAuthenticationRequestLifetime = 5 * time.Minute
const MaximumOIDCAuthenticationRequestsPerProvider = 64

// OIDCAuthenticationRequest is short-lived login state, not evidence. Raw state
// and nonce values are delivered once and never stored in this record.
type OIDCAuthenticationRequest struct {
	ID               string
	TenantID         string
	ProviderID       string
	Delivery         string
	TrustFingerprint string
	StateHash        string
	NonceHash        string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	ConsumedAt       *time.Time
	SchemaVersion    string
}

func (r OIDCAuthenticationRequest) PendingAt(now time.Time) bool {
	return r.ID != "" && r.TenantID != "" && r.ProviderID != "" &&
		(r.Delivery == "api" || r.Delivery == "browser") && r.SchemaVersion == OIDCAuthenticationRequestSchemaVersion &&
		!now.IsZero() && !r.CreatedAt.IsZero() && !now.Before(r.CreatedAt) && r.ExpiresAt.After(now) &&
		!r.ExpiresAt.After(r.CreatedAt.Add(MaximumOIDCAuthenticationRequestLifetime)) && r.ConsumedAt == nil
}
