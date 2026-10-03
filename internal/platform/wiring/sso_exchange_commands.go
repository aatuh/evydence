package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func BuildSSOExchangeCommands(factory app.UnitOfWorkFactory, pepper string, production bool) (*identityapp.SSOExchangeCommands, error) {
	if factory == nil {
		return nil, errors.New("SSO exchange transactions are required")
	}
	credentials, err := buildAuthenticationCredentials(pepper, production)
	if err != nil {
		return nil, err
	}
	return identityapp.NewSSOExchangeCommands(identityapp.SSOExchangeCommandConfig{
		Reader: ssoExchangeReader{factory: factory}, Transactions: ssoExchangeTransactions{factory: factory},
		Credentials: credentials, Verifier: app.LocalSSOCredentialVerifier{}, VerificationPolicy: app.LocalSSOVerificationPolicy{},
		SessionGrants: ssoExchangeGroupPolicy{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID),
	})
}

type ssoExchangeGroupPolicy struct{}

func (ssoExchangeGroupPolicy) GrantsForProviderGroups(p identitydomain.SSOProvider, groups []string) []identitydomain.ResourceGrant {
	return identityapp.ProviderGroupGrants(p, groups)
}

// Each preflight read holds only its bounded point/range projection through
// its short transaction. Credential verification runs outside transactions;
// the final write transaction compares and locks the complete decision snapshot.
type ssoExchangeReader struct{ factory app.UnitOfWorkFactory }

func (r ssoExchangeReader) read(ctx context.Context, fn func(context.Context, identityapp.SSOExchangeReader) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.SSOExchangeReader)
		if !ok {
			return app.ErrValidation
		}
		return fn(ctx, reader)
	}))
}
func (r ssoExchangeReader) SSOProviderByID(ctx context.Context, id string) (identitydomain.SSOProvider, error) {
	var out identitydomain.SSOProvider
	err := r.read(ctx, func(ctx context.Context, reader identityapp.SSOExchangeReader) error {
		var err error
		out, err = reader.SSOProviderByID(ctx, id)
		return err
	})
	return out, err
}
func (r ssoExchangeReader) IdentityLink(ctx context.Context, tenant, provider, subject string) (identitydomain.UserIdentityLink, bool, error) {
	var out identitydomain.UserIdentityLink
	var found bool
	err := r.read(ctx, func(ctx context.Context, reader identityapp.SSOExchangeReader) error {
		var err error
		out, found, err = reader.IdentityLink(ctx, tenant, provider, subject)
		return err
	})
	return out, found, err
}
func (r ssoExchangeReader) User(ctx context.Context, tenant, id string) (identitydomain.HumanUser, error) {
	var out identitydomain.HumanUser
	err := r.read(ctx, func(ctx context.Context, reader identityapp.SSOExchangeReader) error {
		var err error
		out, err = reader.User(ctx, tenant, id)
		return err
	})
	return out, err
}
func (r ssoExchangeReader) UserGrants(ctx context.Context, tenant, id string) ([]identitydomain.ResourceGrant, error) {
	var out []identitydomain.ResourceGrant
	err := r.read(ctx, func(ctx context.Context, reader identityapp.SSOExchangeReader) error {
		var err error
		out, err = reader.UserGrants(ctx, tenant, id)
		return err
	})
	return out, err
}

type ssoExchangeTransactions struct{ factory app.UnitOfWorkFactory }

func (t ssoExchangeTransactions) ExecuteSSOExchange(ctx context.Context, fn func(context.Context, identityapp.SSOExchangeTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		if repos.Identity == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, ssoExchangeTransaction{identity: repos.Identity, audit: repos.Audit})
	}))
}

type ssoExchangeTransaction struct {
	identity app.IdentityRepository
	audit    app.AuditRepository
}

func (t ssoExchangeTransaction) ValidateSSOExchangeState(ctx context.Context, s identityapp.SSOExchangeSnapshot) error {
	grants := make([]domain.ResourceGrant, len(s.UserGrants))
	for i, g := range s.UserGrants {
		grants[i] = domain.ResourceGrant(g)
	}
	return mapAPIKeyWriteError(t.identity.ValidateSSOExchangeState(ctx, app.SSOExchangeSnapshot{Provider: domain.SSOProvider(s.Provider), Subject: s.Subject, IdentityLink: domain.UserIdentityLink(s.IdentityLink), IdentityLinkFound: s.IdentityLinkFound, User: domain.HumanUser(s.User), UserLoaded: s.UserLoaded, UserFound: s.UserFound, UserGrants: grants, UserGrantsLoaded: s.UserGrantsLoaded}))
}
func (t ssoExchangeTransaction) InsertProviderVerification(ctx context.Context, v identitydomain.ProviderVerification) error {
	return mapAPIKeyWriteError(t.identity.InsertProviderVerification(ctx, app.ProviderVerificationFromIdentity(v)))
}
func (t ssoExchangeTransaction) InsertSSOSession(ctx context.Context, v identitydomain.SSOSession) error {
	return mapAPIKeyWriteError(t.identity.InsertSSOSession(ctx, domain.SSOSession(v)))
}
func (t ssoExchangeTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	out, err := appendAuditEvent(ctx, t.audit, v)
	return out, mapAPIKeyWriteError(err)
}
