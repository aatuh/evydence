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

func BuildRoleBindingCommands(factory app.UnitOfWorkFactory) (*identityapp.RoleBindingCommands, error) {
	if factory == nil {
		return nil, errors.New("role binding transactions are required")
	}
	return identityapp.NewRoleBindingCommands(identityapp.RoleBindingCommandConfig{Transactions: roleBindingTransactions{factory}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type roleBindingTransactions struct{ factory app.UnitOfWorkFactory }

func (t roleBindingTransactions) ExecuteRoleBinding(ctx context.Context, fn func(context.Context, identityapp.RoleBindingTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.RoleBindingWriteReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, roleBindingTransaction{reader, repos.Identity, repos.Audit})
	}))
}

type roleBindingTransaction struct {
	identityapp.RoleBindingWriteReader
	identity interface {
		InsertRoleBinding(context.Context, domain.RoleBinding) error
	}
	audit app.AuditRepository
}

func (t roleBindingTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (t roleBindingTransaction) InsertRoleBinding(ctx context.Context, v identitydomain.RoleBinding) error {
	return mapAPIKeyWriteError(t.identity.InsertRoleBinding(ctx, domain.RoleBinding(v)))
}
func (t roleBindingTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	out, err := appendAuditEvent(ctx, t.audit, v)
	return out, mapAPIKeyWriteError(err)
}
