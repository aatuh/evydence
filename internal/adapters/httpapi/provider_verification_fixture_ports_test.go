package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Real focused provider receipt commands use active transaction repositories,
// not Ledger caches. Fake provider calls are not undone by rollback and do not
// establish provider trust or SQL locking/durability.
type providerVerificationFixtureCommands struct {
	catalogFixtureCommands
	live  app.ProviderIdentityValidator
	clock application.Clock
}
type providerVerificationFixtureReader struct {
	catalogFixtureCommands
	readOnly bool
}
type providerVerificationGuardSentinel struct{}

func (f providerVerificationFixtureReader) ReadOwnedSSOProvider(ctx context.Context, tenant, id string) (identitydomain.SSOProvider, error) {
	var out identitydomain.SSOProvider
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.ProviderVerificationReader)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		var err error
		out, err = reader.ReadOwnedSSOProvider(ctx, tenant, id)
		return err
	})
	return out, err
}
func (f providerVerificationFixtureReader) IdentityLink(ctx context.Context, tenant, provider, subject string) (identitydomain.UserIdentityLink, bool, error) {
	if f.readOnly {
		panic("provider preflight read identity links")
	}
	var out identitydomain.UserIdentityLink
	var found bool
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.ProviderVerificationReader)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canFence {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		var err error
		out, found, err = reader.IdentityLink(ctx, tenant, provider, subject)
		return err
	})
	return out, found, err
}
func (providerVerificationGuardSentinel) ExecuteProviderVerification(context.Context, func(context.Context, identityapp.ProviderVerificationTransaction) error) error {
	panic("provider preflight wrote receipt")
}
func (providerVerificationGuardSentinel) Verify(context.Context, identityapp.CredentialVerificationRequest) (identityapp.CredentialVerificationResult, error) {
	panic("provider preflight verified credentials")
}
func (providerVerificationGuardSentinel) ValidateProviderIdentity(context.Context, identityapp.ProviderIdentityValidationRequest) (identityapp.ProviderIdentityValidationResult, error) {
	panic("provider preflight contacted provider")
}
func (f providerVerificationFixtureCommands) AuthorizeVerifyProviderIdentity(ctx context.Context, a domain.Actor, in identityapp.VerifyProviderIdentityInput) error {
	g, err := f.nativeProviderVerification(true)
	if err != nil {
		return err
	}
	return g.AuthorizeVerifyProviderIdentity(ctx, a, in)
}
func (f providerVerificationFixtureCommands) VerifyProviderIdentity(ctx context.Context, a domain.Actor, in identityapp.VerifyProviderIdentityInput) (identitydomain.ProviderVerification, error) {
	c, err := f.nativeProviderVerification(false)
	if err != nil {
		return identitydomain.ProviderVerification{}, err
	}
	v, err := c.VerifyProviderIdentity(ctx, a, in)
	return v, providerVerificationFixtureError(err)
}
func (s *Server) bindProviderVerificationFixturePort(ledger *app.Ledger) {
	if old, fixture := s.providerVerificationCommands.(providerVerificationFixtureCommands); fixture {
		old.ledger = ledger
		s.providerVerificationCommands = old
	} else if s.providerVerificationCommands == nil {
		s.providerVerificationCommands = providerVerificationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	}
}

var _ ProviderVerificationCommands = providerVerificationFixtureCommands{}
