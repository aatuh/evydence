package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Only historical tests use this bridge. Native read-only preflight uses the
// existing bounded provider reader; actual receipt writes use the isolated
// command clone. This is not native SQL locking or provider trust evidence.
type providerVerificationFixtureCommands struct{ catalogFixtureCommands }
type providerVerificationFixtureReader struct{ catalogFixtureCommands }
type providerVerificationGuardSentinel struct{}

func (f providerVerificationFixtureReader) ReadOwnedSSOProvider(ctx context.Context, tenant, id string) (identitydomain.SSOProvider, error) {
	var out identitydomain.SSOProvider
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(interface {
			ReadOwnedSSOProvider(context.Context, string, string) (identitydomain.SSOProvider, error)
		})
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.ReadOwnedSSOProvider(ctx, tenant, id)
		return err
	})
	return out, err
}
func (providerVerificationFixtureReader) IdentityLink(context.Context, string, string, string) (identitydomain.UserIdentityLink, bool, error) {
	panic("provider preflight read identity links")
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
	g, err := identityapp.NewProviderVerificationCommands(identityapp.ProviderVerificationCommandConfig{Reader: providerVerificationFixtureReader(f), Transactions: providerVerificationGuardSentinel{}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Verifier: providerVerificationGuardSentinel{}, LiveProvider: providerVerificationGuardSentinel{}, VerificationPolicy: app.LocalSSOVerificationPolicy{}, Clock: application.ClockFunc(membershipFixtureClock), IDs: application.IDGeneratorFunc(membershipFixtureID)})
	if err != nil {
		return err
	}
	return g.AuthorizeVerifyProviderIdentity(ctx, a, in)
}
func (f providerVerificationFixtureCommands) VerifyProviderIdentity(ctx context.Context, a domain.Actor, in identityapp.VerifyProviderIdentityInput) (identitydomain.ProviderVerification, error) {
	v, err := f.commandLedger(ctx).VerifyProviderIdentity(ctx, a, app.VerifyProviderIdentityInput{ProviderType: in.ProviderType, ProviderID: in.ProviderID, Subject: in.Subject, IDToken: in.IDToken, SAMLAssertion: in.SAMLAssertion, AccessToken: in.AccessToken})
	return ssoFixtureVerificationModel(v), err
}
func (s *Server) bindProviderVerificationFixturePort(ledger *app.Ledger) {
	if _, fixture := s.providerVerificationCommands.(providerVerificationFixtureCommands); s.providerVerificationCommands == nil || fixture {
		s.providerVerificationCommands = providerVerificationFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	}
}

var _ ProviderVerificationCommands = providerVerificationFixtureCommands{}
