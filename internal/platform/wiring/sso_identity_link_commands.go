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

func BuildSSOIdentityLinkCommands(factory app.UnitOfWorkFactory) (*identityapp.SSOIdentityLinkCommands, error) {
	if factory == nil {
		return nil, errors.New("identity link transactions are required")
	}
	return identityapp.NewSSOIdentityLinkCommands(identityapp.SSOIdentityLinkCommandConfig{Transactions: identityLinkTransactions{factory}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type identityLinkTransactions struct{ factory app.UnitOfWorkFactory }

func (t identityLinkTransactions) ExecuteSSOIdentityLink(ctx context.Context, fn func(context.Context, identityapp.SSOIdentityLinkTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.SSOIdentityLinkWriteReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, identityLinkTransaction{reader, repos.Identity, repos.Audit})
	}))
}

type identityLinkTransaction struct {
	identityapp.SSOIdentityLinkWriteReader
	identity interface {
		InsertUserIdentityLink(context.Context, domain.UserIdentityLink) error
	}
	audit app.AuditRepository
}

func (t identityLinkTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (t identityLinkTransaction) InsertUserIdentityLink(ctx context.Context, v identitydomain.UserIdentityLink) error {
	return mapAPIKeyWriteError(t.identity.InsertUserIdentityLink(ctx, domain.UserIdentityLink(v)))
}
func (t identityLinkTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	out, err := appendAuditEvent(ctx, t.audit, v)
	return out, mapAPIKeyWriteError(err)
}
