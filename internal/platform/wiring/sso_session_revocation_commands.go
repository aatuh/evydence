package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func BuildSSOSessionRevocationCommands(factory app.UnitOfWorkFactory) (*identityapp.SSOSessionRevocationCommands, error) {
	if factory == nil {
		return nil, errors.New("session revocation transactions are required")
	}
	return identityapp.NewSSOSessionRevocationCommands(identityapp.SSOSessionRevocationConfig{Transactions: sessionRevocationTransactions{factory}, Authorizer: identityapp.NewSSOSessionRevocationAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type sessionRevocationTransactions struct{ factory app.UnitOfWorkFactory }

func (t sessionRevocationTransactions) ExecuteSSOSessionRevocation(ctx context.Context, fn func(context.Context, identityapp.SSOSessionRevocationTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.SSOSessionRevocationReader)
		writer, canWrite := repos.Identity.(interface {
			RevokeSSOSessionMetadata(context.Context, identitydomain.SSOSession, time.Time) error
		})
		if !ok || !canWrite || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, sessionRevocationTransaction{reader, writer, repos.Audit})
	}))
}

type sessionRevocationTransaction struct {
	identityapp.SSOSessionRevocationReader
	writer interface {
		RevokeSSOSessionMetadata(context.Context, identitydomain.SSOSession, time.Time) error
	}
	audit app.AuditRepository
}

func (t sessionRevocationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewSSOSessionRevocationAuthorizer().Authorize(ctx, a, r)
}
func (t sessionRevocationTransaction) RevokeSSOSessionMetadata(ctx context.Context, v identitydomain.SSOSession, now time.Time) error {
	return mapAPIKeyWriteError(t.writer.RevokeSSOSessionMetadata(ctx, v, now))
}
func (t sessionRevocationTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	out, err := appendAuditEvent(ctx, t.audit, v)
	return out, mapAPIKeyWriteError(err)
}
