package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Session and API-key credentials use the focused authenticator and current
// repository reads; neither branch consults the aggregate's credential caches.
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
	return (identityNativeFixtureAuthenticator{f}).Authenticate(ctx, secret)
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
