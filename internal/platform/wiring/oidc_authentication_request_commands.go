package wiring

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func BuildOIDCAuthenticationRequestCommands(factory app.UnitOfWorkFactory, pepper string, production bool) (*identityapp.OIDCAuthenticationRequestCommands, error) {
	if factory == nil {
		return nil, identityapp.ErrValidation
	}
	credentials, err := buildAuthenticationCredentials(pepper, production)
	if err != nil {
		return nil, err
	}
	return identityapp.NewOIDCAuthenticationRequestCommands(identityapp.OIDCAuthenticationRequestCommandConfig{
		Reader: ssoExchangeReader{factory: factory}, Transactions: oidcRequestTransactions{factory}, Credentials: credentials,
		Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID),
	})
}

type oidcRequestTransactions struct{ factory app.UnitOfWorkFactory }
type oidcRequestTransaction struct {
	identity interface {
		ValidateOIDCProvider(context.Context, identitydomain.SSOProvider) error
		InsertOIDCAuthenticationRequest(context.Context, identitydomain.OIDCAuthenticationRequest, time.Time) error
	}
	audit app.AuditRepository
}

func (t oidcRequestTransactions) ExecuteOIDCAuthenticationRequest(ctx context.Context, fn func(context.Context, identityapp.OIDCAuthenticationRequestTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		writer, ok := repos.Identity.(interface {
			ValidateOIDCProvider(context.Context, identitydomain.SSOProvider) error
			InsertOIDCAuthenticationRequest(context.Context, identitydomain.OIDCAuthenticationRequest, time.Time) error
		})
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, oidcRequestTransaction{writer, repos.Audit})
	}))
}
func (t oidcRequestTransaction) ValidateOIDCProvider(ctx context.Context, p identitydomain.SSOProvider) error {
	return mapAPIKeyWriteError(t.identity.ValidateOIDCProvider(ctx, p))
}
func (t oidcRequestTransaction) InsertOIDCAuthenticationRequest(ctx context.Context, v identitydomain.OIDCAuthenticationRequest, at time.Time) error {
	return mapAPIKeyWriteError(t.identity.InsertOIDCAuthenticationRequest(ctx, v, at))
}
func (t oidcRequestTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapAPIKeyWriteError(err)
}
