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

func BuildMembershipCommands(factory app.UnitOfWorkFactory) (*identityapp.MembershipCommands, error) {
	if factory == nil {
		return nil, errors.New("membership transactions are required")
	}
	return identityapp.NewMembershipCommands(identityapp.MembershipCommandConfig{Transactions: membershipTransactions{factory}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type membershipTransactions struct{ factory app.UnitOfWorkFactory }

func (t membershipTransactions) ExecuteMembership(ctx context.Context, fn func(context.Context, identityapp.MembershipTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.MembershipWriteReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, membershipTransaction{reader, repos.Identity, repos.Audit})
	}))
}

type membershipTransaction struct {
	identityapp.MembershipWriteReader
	identity interface {
		InsertOrganization(context.Context, domain.Organization) error
		InsertHumanUser(context.Context, domain.HumanUser) error
		DeactivateHumanUser(context.Context, domain.HumanUser) error
	}
	audit app.AuditRepository
}

func (t membershipTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (t membershipTransaction) InsertOrganization(ctx context.Context, v identitydomain.Organization) error {
	return mapAPIKeyWriteError(t.identity.InsertOrganization(ctx, domain.Organization(v)))
}
func (t membershipTransaction) InsertHumanUser(ctx context.Context, v identitydomain.HumanUser) error {
	return mapAPIKeyWriteError(t.identity.InsertHumanUser(ctx, domain.HumanUser(v)))
}
func (t membershipTransaction) DeactivateHumanUser(ctx context.Context, v identitydomain.HumanUser) error {
	return mapAPIKeyWriteError(t.identity.DeactivateHumanUser(ctx, domain.HumanUser(v)))
}
func (t membershipTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapAPIKeyWriteError(err)
}
