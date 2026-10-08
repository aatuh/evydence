package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type providerVerificationNativeTransactions struct{ catalogFixtureCommands }
type providerVerificationNativeTransaction struct{ repos app.Repositories }

func (f providerVerificationNativeTransactions) ExecuteProviderVerification(ctx context.Context, fn func(context.Context, identityapp.ProviderVerificationTransaction) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		if repos.Identity == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, providerVerificationNativeTransaction{repos})
	})
}
func (tx providerVerificationNativeTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (tx providerVerificationNativeTransaction) ValidateSSOExchangeState(ctx context.Context, s identityapp.SSOExchangeSnapshot) error {
	// A receipt does not load a user/grant snapshot or issue a session.
	if s.UserLoaded || s.UserFound || s.UserGrantsLoaded || len(s.UserGrants) != 0 {
		return app.ErrValidation
	}
	return tx.repos.Identity.ValidateSSOExchangeState(ctx, app.SSOExchangeSnapshot{Provider: domain.SSOProvider(s.Provider), Subject: s.Subject, IdentityLink: domain.UserIdentityLink(s.IdentityLink), IdentityLinkFound: s.IdentityLinkFound})
}
func (tx providerVerificationNativeTransaction) InsertProviderVerification(ctx context.Context, v identitydomain.ProviderVerification) error {
	return tx.repos.Identity.InsertProviderVerification(ctx, app.ProviderVerificationFromIdentity(v))
}
func (tx providerVerificationNativeTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	return (portalFixtureTransaction{repos: tx.repos}).AppendAudit(ctx, v)
}
func providerVerificationFixtureClock() application.Clock {
	return application.ClockFunc(peripheralFixtureQueryClock)
}
func (f providerVerificationFixtureCommands) nativeProviderVerification(readOnly bool) (*identityapp.ProviderVerificationCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	var tx identityapp.ProviderVerificationTransactions = providerVerificationNativeTransactions{f.catalogFixtureCommands}
	var verifier identityapp.CredentialVerifier = app.LocalSSOCredentialVerifier{}
	var live identityapp.ProviderIdentityValidator
	if f.live != nil {
		live = app.IdentityProviderAPIValidator{Client: f.live}
	}
	if readOnly {
		tx = providerVerificationGuardSentinel{}
		verifier = providerVerificationGuardSentinel{}
		live = providerVerificationGuardSentinel{}
	}
	return identityapp.NewProviderVerificationCommands(identityapp.ProviderVerificationCommandConfig{Reader: providerVerificationFixtureReader{f.catalogFixtureCommands, readOnly}, Transactions: tx, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Verifier: verifier, LiveProvider: live, VerificationPolicy: app.LocalSSOVerificationPolicy{}, Clock: clock, IDs: ids})
}
func (s *Server) bindProviderVerificationFixtureResources(live app.ProviderIdentityValidator, clock application.Clock) {
	if f, ok := s.providerVerificationCommands.(providerVerificationFixtureCommands); ok {
		f.live, f.clock = live, clock
		s.providerVerificationCommands = f
	}
}
func providerVerificationFixtureError(err error) error {
	switch {
	case errors.Is(err, identityapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, identityapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, identityapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, identityapp.ErrVerificationFailed):
		return app.ErrVerificationFailed
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
