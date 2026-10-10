package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// Historical aggregate entry points are characterization only. External test
// setup and production composition use real focused identity commands.
func (l *Ledger) BootstrapTenant(ctx context.Context, name, keyName string, scopes []string) (domain.Tenant, domain.APIKey, string, error) {
	return l.bootstrapTenant(ctx, identityapp.BootstrapTenantInput{
		TenantName: name, APIKeyName: keyName, Scopes: scopes,
	})
}

func (l *Ledger) Authenticate(ctx context.Context, secret string) (domain.Actor, error) {
	actor, err := l.legacyIdentityCommands().Authenticate(ctx, secret)
	return actor, fromIdentityContextError(err)
}
