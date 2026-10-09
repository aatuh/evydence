package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Explicit credentials and clock configure the real focused authenticator.
// It never falls back to Ledger credential, collector or session caches.
type identityNativeFixtureAuthenticator struct{ ssoFixtureAuthenticator }

func fixtureIdentityAuthenticator(ledger *app.Ledger, pepper string, clock application.Clock) identityNativeFixtureAuthenticator {
	return identityNativeFixtureAuthenticator{fixtureSessionAuthenticator(ledger, pepper, clock)}
}
func (f identityNativeFixtureAuthenticator) Authenticate(ctx context.Context, secret string) (domain.Actor, error) {
	c, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{Reader: f, Activity: f, Credentials: f.credentials, Clock: f.clock})
	if err != nil {
		return domain.Actor{}, providerVerificationFixtureError(err)
	}
	v, err := c.Authenticate(ctx, secret)
	return v, providerVerificationFixtureError(err)
}
func (f identityNativeFixtureAuthenticator) APIKeysByPrefix(ctx context.Context, prefix string) ([]identitydomain.APIKey, error) {
	var out []identitydomain.APIKey
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Identity.(identityapp.AuthenticationReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.APIKeysByPrefix(ctx, prefix)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (f identityNativeFixtureAuthenticator) CollectorByAPIKey(ctx context.Context, tenant, key string) (identityapp.CollectorBinding, bool, error) {
	var out identityapp.CollectorBinding
	var found bool
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Identity.(identityapp.AuthenticationReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, found, err = reader.CollectorByAPIKey(ctx, tenant, key)
		return err
	})
	if err != nil {
		return identityapp.CollectorBinding{}, false, err
	}
	return out, found, nil
}
func (f identityNativeFixtureAuthenticator) RecordAPIKeyUse(ctx context.Context, key identitydomain.APIKey, activity identityapp.CollectorActivity) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		writer, ok := r.Identity.(interface {
			RecordAPIKeyUse(context.Context, identitydomain.APIKey, identityapp.CollectorActivity) error
		})
		if !ok {
			return app.ErrValidation
		}
		return writer.RecordAPIKeyUse(ctx, key, activity)
	})
}
