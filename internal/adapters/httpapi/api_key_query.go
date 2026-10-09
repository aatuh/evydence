package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func apiKeyFromQuery(key identitydomain.APIKey) domain.APIKey {
	return domain.APIKey{
		ID: key.ID, TenantID: key.TenantID, Name: key.Name, Prefix: key.Prefix,
		Scopes: key.Scopes, CreatedAt: key.CreatedAt, ExpiresAt: key.ExpiresAt,
		RevokedAt: key.RevokedAt, LastUsedAt: key.LastUsedAt,
	}
}
