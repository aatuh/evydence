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

func BuildSSOProviderCommands(factory app.UnitOfWorkFactory) (*identityapp.SSOProviderCommands, error) {
	if factory == nil {
		return nil, errors.New("SSO provider transactions are required")
	}
	return identityapp.NewSSOProviderCommands(identityapp.SSOProviderCommandConfig{Transactions: ssoProviderTransactions{factory}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), TrustMaterial: identityapp.PublicTrustMaterialValidator{}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type ssoProviderTransactions struct{ factory app.UnitOfWorkFactory }

func (t ssoProviderTransactions) ExecuteSSOProvider(ctx context.Context, fn func(context.Context, identityapp.SSOProviderTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.SSOProviderWriteReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, ssoProviderTransaction{reader, repos.Identity, repos.Audit})
	}))
}

type ssoProviderTransaction struct {
	identityapp.SSOProviderWriteReader
	identity interface {
		InsertSSOProvider(context.Context, domain.SSOProvider) error
	}
	audit app.AuditRepository
}

func (t ssoProviderTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (t ssoProviderTransaction) InsertSSOProvider(ctx context.Context, v identitydomain.SSOProvider) error {
	return mapAPIKeyWriteError(t.identity.InsertSSOProvider(ctx, domain.SSOProvider(v)))
}
func (t ssoProviderTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	out, err := appendAuditEvent(ctx, t.audit, v)
	return out, mapAPIKeyWriteError(err)
}
