package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// LocalDevelopmentPepper preserves the explicit non-production compatibility
// default. Production wiring must reject this value.
const LocalDevelopmentPepper = "local-dev-pepper-change-me"

// HMACAuthenticationCredentials verifies the existing persisted API-key and
// SSO-session hash format without requiring a Ledger instance.
type HMACAuthenticationCredentials struct{ pepper []byte }

func NewHMACAuthenticationCredentials(pepper string) (*HMACAuthenticationCredentials, error) {
	pepper = strings.TrimSpace(pepper)
	if pepper == "" {
		return nil, ErrValidation
	}
	return &HMACAuthenticationCredentials{pepper: []byte(pepper)}, nil
}

func (*HMACAuthenticationCredentials) Prefix(secret string) string {
	if len(secret) <= 12 {
		return secret
	}
	return secret[:12]
}

func (c *HMACAuthenticationCredentials) Hash(secret string) string {
	mac := hmac.New(sha256.New, c.pepper)
	_, _ = mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

func (*HMACAuthenticationCredentials) Equal(stored, candidate string) bool {
	if len(stored) != sha256.Size*2 || len(candidate) != sha256.Size*2 {
		return false
	}
	return hmac.Equal([]byte(stored), []byte(candidate))
}
