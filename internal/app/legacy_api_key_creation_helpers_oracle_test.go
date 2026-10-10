package app

import (
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical cache-only issuance remains solely for characterization.
func (l *Ledger) createAPIKeyLocked(tenantID, name string, scopes []string, expiresAt *time.Time) (domain.APIKey, string, error) {
	key, secret := l.newAPIKey(tenantID, name, scopes, expiresAt)
	l.apiKeys[key.ID] = key
	public := key
	public.Hash = ""
	return public, secret, nil
}

// newAPIKey derives a credential and its stored hash without publishing either
// value to the process read model. Transactional callers must persist key
// material before returning the bearer secret to the caller.
func (l *Ledger) newAPIKey(tenantID, name string, scopes []string, expiresAt *time.Time) (domain.APIKey, string) {
	secret := "evy_" + randomToken(32)
	key := domain.APIKey{ID: newID("key"), TenantID: tenantID, Name: name, Prefix: secretPrefix(secret), Scopes: sortedStrings(scopes), CreatedAt: l.now(), ExpiresAt: expiresAt, Hash: l.hashSecret(secret)}
	return key, secret
}
