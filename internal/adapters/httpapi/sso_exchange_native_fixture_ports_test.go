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

type ssoExchangeNativeReader struct{ catalogFixtureCommands }

func ssoExchangeNativeError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return identityapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return identityapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return identityapp.ErrConflict
	default:
		return err
	}
}
func (r ssoExchangeNativeReader) read(ctx context.Context, run func(context.Context, identityapp.SSOExchangeReader) error) error {
	return ssoExchangeNativeError(r.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.SSOExchangeReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, reader)
	}))
}
func (r ssoExchangeNativeReader) SSOProviderByID(ctx context.Context, id string) (identitydomain.SSOProvider, error) {
	var out identitydomain.SSOProvider
	err := r.read(ctx, func(ctx context.Context, reader identityapp.SSOExchangeReader) error {
		var err error
		out, err = reader.SSOProviderByID(ctx, id)
		return err
	})
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	return out, nil
}
func (r ssoExchangeNativeReader) IdentityLink(ctx context.Context, tenant, provider, subject string) (identitydomain.UserIdentityLink, bool, error) {
	var out identitydomain.UserIdentityLink
	var found bool
	err := r.read(ctx, func(ctx context.Context, reader identityapp.SSOExchangeReader) error {
		var err error
		out, found, err = reader.IdentityLink(ctx, tenant, provider, subject)
		return err
	})
	if err != nil {
		return identitydomain.UserIdentityLink{}, false, err
	}
	return out, found, nil
}
func (r ssoExchangeNativeReader) User(ctx context.Context, tenant, id string) (identitydomain.HumanUser, error) {
	var out identitydomain.HumanUser
	err := r.read(ctx, func(ctx context.Context, reader identityapp.SSOExchangeReader) error {
		var err error
		out, err = reader.User(ctx, tenant, id)
		return err
	})
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	return out, nil
}
func (r ssoExchangeNativeReader) UserGrants(ctx context.Context, tenant, id string) ([]identitydomain.ResourceGrant, error) {
	var out []identitydomain.ResourceGrant
	err := r.read(ctx, func(ctx context.Context, reader identityapp.SSOExchangeReader) error {
		var err error
		out, err = reader.UserGrants(ctx, tenant, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type ssoExchangeNativeTransactions struct{ catalogFixtureCommands }
type ssoExchangeNativeTransaction struct{ repos app.Repositories }

func (f ssoExchangeNativeTransactions) ExecuteSSOExchange(ctx context.Context, run func(context.Context, identityapp.SSOExchangeTransaction) error) error {
	return ssoExchangeNativeError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		if repos.Identity == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, ssoExchangeNativeTransaction{repos})
	}))
}
func (tx ssoExchangeNativeTransaction) ValidateSSOExchangeState(ctx context.Context, s identityapp.SSOExchangeSnapshot) error {
	grants := make([]domain.ResourceGrant, len(s.UserGrants))
	for i, g := range s.UserGrants {
		grants[i] = domain.ResourceGrant(g)
	}
	return tx.repos.Identity.ValidateSSOExchangeState(ctx, app.SSOExchangeSnapshot{Provider: domain.SSOProvider(s.Provider), Subject: s.Subject, IdentityLink: domain.UserIdentityLink(s.IdentityLink), IdentityLinkFound: s.IdentityLinkFound, User: domain.HumanUser(s.User), UserLoaded: s.UserLoaded, UserFound: s.UserFound, UserGrants: grants, UserGrantsLoaded: s.UserGrantsLoaded})
}
func (tx ssoExchangeNativeTransaction) InsertProviderVerification(ctx context.Context, v identitydomain.ProviderVerification) error {
	return tx.repos.Identity.InsertProviderVerification(ctx, app.ProviderVerificationFromIdentity(v))
}
func (tx ssoExchangeNativeTransaction) InsertSSOSession(ctx context.Context, v identitydomain.SSOSession) error {
	return tx.repos.Identity.InsertSSOSession(ctx, domain.SSOSession(v))
}
func (tx ssoExchangeNativeTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	return (portalFixtureTransaction{repos: tx.repos}).AppendAudit(ctx, v)
}

type ssoExchangeNativeGroupPolicy struct{}

func (ssoExchangeNativeGroupPolicy) GrantsForProviderGroups(p identitydomain.SSOProvider, groups []string) []identitydomain.ResourceGrant {
	return identityapp.ProviderGroupGrants(p, groups)
}

func (f ssoSessionFixtureCommands) exchangeCommands() (*identityapp.SSOExchangeCommands, error) {
	clock, ids := f.clockIDs(false)
	credentials := f.credentials
	if credentials == nil {
		credentials = fixtureSessionCredentials("test")
	}
	return identityapp.NewSSOExchangeCommands(identityapp.SSOExchangeCommandConfig{Reader: ssoExchangeNativeReader{f.catalogFixtureCommands}, Transactions: ssoExchangeNativeTransactions{f.catalogFixtureCommands}, Credentials: credentials, Verifier: app.LocalSSOCredentialVerifier{}, VerificationPolicy: app.LocalSSOVerificationPolicy{}, SessionGrants: ssoExchangeNativeGroupPolicy{}, Clock: clock, IDs: ids})
}
