package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// Unchanged historical declarations retained for package-local regression
// oracles. Production API-key issuance and pages belong to focused services.
func (l *Ledger) CreateAPIKey(ctx context.Context, actor domain.Actor, name string, scopes []string, expiresAt *time.Time) (domain.APIKey, string, error) {
	key, secret, err := l.identityCommands.CreateAPIKey(ctx, actor, identityapp.CreateAPIKeyInput{Name: name, Scopes: scopes, ExpiresAt: expiresAt})
	return apiKeyFromIdentityContext(key), secret, fromIdentityContextError(err)
}

func (l *Ledger) ListAPIKeys(ctx context.Context, actor domain.Actor) ([]domain.APIKey, error) {
	keys, err := l.identityCommands.ListAPIKeys(ctx, actor)
	if err != nil {
		return nil, fromIdentityContextError(err)
	}
	result := make([]domain.APIKey, 0, len(keys))
	for _, key := range keys {
		result = append(result, apiKeyFromIdentityContext(key))
	}
	return result, nil
}
