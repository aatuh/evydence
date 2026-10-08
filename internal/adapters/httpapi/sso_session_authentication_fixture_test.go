package httpapi

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Session credentials use the real focused authenticator and bounded current
// repository reads. API-key setup remains a historical test-only dependency.
type ssoFixtureAuthenticator struct {
	catalogFixtureCommands
	credentials *identityapp.HMACAuthenticationCredentials
	clock       application.Clock
}

func fixtureSessionCredentials(pepper string) *identityapp.HMACAuthenticationCredentials {
	c, err := identityapp.NewHMACAuthenticationCredentials(pepper)
	if err != nil {
		panic("invalid fixture session pepper")
	}
	return c
}
func fixtureSessionAuthenticator(ledger *app.Ledger, pepper string, clock application.Clock) ssoFixtureAuthenticator {
	if clock == nil {
		clock = application.ClockFunc(time.Now)
	}
	return ssoFixtureAuthenticator{catalogFixtureCommands{ledger}, fixtureSessionCredentials(pepper), clock}
}
func (f ssoFixtureAuthenticator) Authenticate(ctx context.Context, secret string) (domain.Actor, error) {
	if !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(secret, "Bearer ")), "evysso_") {
		return f.ledger.Authenticate(ctx, secret)
	}
	c, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{Reader: f, Activity: f, Credentials: f.credentials, Clock: f.clock})
	if err != nil {
		return domain.Actor{}, providerVerificationFixtureError(err)
	}
	v, err := c.Authenticate(ctx, secret)
	return v, providerVerificationFixtureError(err)
}
func (ssoFixtureAuthenticator) APIKeysByPrefix(ctx context.Context, _ string) ([]identitydomain.APIKey, error) {
	return nil, ctx.Err()
}
func (ssoFixtureAuthenticator) CollectorByAPIKey(context.Context, string, string) (identityapp.CollectorBinding, bool, error) {
	panic("session-only authentication read collectors")
}
func (ssoFixtureAuthenticator) RecordAPIKeyUse(context.Context, identitydomain.APIKey, identityapp.CollectorActivity) error {
	panic("session-only authentication changed API keys")
}
func (f ssoFixtureAuthenticator) SessionsByPrefix(ctx context.Context, prefix string) ([]identitydomain.SSOSession, error) {
	var out []identitydomain.SSOSession
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Identity.(interface {
			SessionsByPrefix(context.Context, string) ([]identitydomain.SSOSession, error)
		})
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = r.SessionsByPrefix(ctx, prefix)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (f ssoFixtureAuthenticator) SessionIdentity(ctx context.Context, session identitydomain.SSOSession) (identityapp.SessionIdentity, error) {
	var out identityapp.SessionIdentity
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Identity.(interface {
			SessionIdentity(context.Context, identitydomain.SSOSession) (identityapp.SessionIdentity, error)
		})
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = r.SessionIdentity(ctx, session)
		return err
	})
	if err != nil {
		return identityapp.SessionIdentity{}, err
	}
	return out, nil
}
func (f ssoFixtureAuthenticator) ValidateActiveSession(ctx context.Context, session identitydomain.SSOSession, now time.Time) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.ValidateActiveSSOSession(ctx, domain.SSOSession(session), now)
	})
}

var _ Authenticator = ssoFixtureAuthenticator{}
