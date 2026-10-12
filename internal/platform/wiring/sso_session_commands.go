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

func BuildSSOSessionCommands(factory app.UnitOfWorkFactory, pepper string, production bool, policies ...identitydomain.SessionPolicy) (*identityapp.SSOSessionCommands, error) {
	if factory == nil {
		return nil, errors.New("session transactions are required")
	}
	policy, err := configuredSessionPolicy(policies)
	if err != nil {
		return nil, err
	}
	credentials, err := buildAuthenticationCredentials(pepper, production)
	if err != nil {
		return nil, err
	}
	return identityapp.NewSSOSessionCommands(identityapp.SSOSessionCommandConfig{Transactions: sessionTransactions{factory}, Credentials: credentials, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID), SessionPolicy: policy})
}

func configuredSessionPolicy(policies []identitydomain.SessionPolicy) (identitydomain.SessionPolicy, error) {
	if len(policies) > 1 {
		return identitydomain.SessionPolicy{}, identityapp.ErrValidation
	}
	var policy identitydomain.SessionPolicy
	if len(policies) == 1 {
		policy = policies[0]
	}
	policy, ok := policy.Normalized()
	if !ok {
		return identitydomain.SessionPolicy{}, identityapp.ErrValidation
	}
	return policy, nil
}

type sessionTransactions struct{ factory app.UnitOfWorkFactory }

func (t sessionTransactions) ExecuteSSOSession(ctx context.Context, fn func(context.Context, identityapp.SSOSessionTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.SSOSessionWriteReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, sessionTransaction{reader, repos.Identity, repos.Audit})
	}))
}

type sessionTransaction struct {
	identityapp.SSOSessionWriteReader
	identity interface {
		InsertSSOSession(context.Context, domain.SSOSession) error
	}
	audit app.AuditRepository
}

func (t sessionTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (t sessionTransaction) InsertSSOSession(ctx context.Context, v identitydomain.SSOSession) error {
	return mapAPIKeyWriteError(t.identity.InsertSSOSession(ctx, domain.SSOSession(v)))
}
func (t sessionTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	out, err := appendAuditEvent(ctx, t.audit, v)
	return out, mapAPIKeyWriteError(err)
}
