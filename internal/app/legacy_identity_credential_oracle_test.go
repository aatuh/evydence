package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// Historical credential adapters pin stored format compatibility without
// retaining a production dependency on the aggregate or its pepper field.
type ledgerCredentialManager struct{ ledger *Ledger }

func (m ledgerCredentialManager) Generate() (identityapp.Credential, error) {
	secret := "evy_" + randomToken(32)
	return identityapp.Credential{Secret: secret, Prefix: secretPrefix(secret), Hash: m.ledger.hashSecret(secret)}, nil
}

func (m ledgerCredentialManager) Prefix(secret string) string { return secretPrefix(secret) }
func (m ledgerCredentialManager) Hash(secret string) string   { return m.ledger.hashSecret(secret) }
func (ledgerCredentialManager) Equal(stored, candidate string) bool {
	return secretHashEqual(stored, candidate)
}

type ledgerSessionCredentialManager struct{ ledger *Ledger }

func (m ledgerSessionCredentialManager) GenerateSession() (identityapp.Credential, error) {
	secret := "evysso_" + randomToken(32)
	return identityapp.Credential{Secret: secret, Prefix: secretPrefix(secret), Hash: m.ledger.hashSecret(secret)}, nil
}

func (l *Ledger) hashSecret(secret string) string {
	mac := hmac.New(sha256.New, l.pepper)
	_, _ = mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}
