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

func BuildAPIKeyCommands(factory app.UnitOfWorkFactory, pepper string, production bool) (*identityapp.APIKeyCommands, error) {
	if factory == nil {
		return nil, errors.New("API key transactions are required")
	}
	credentials, err := buildAuthenticationCredentials(pepper, production)
	if err != nil {
		return nil, err
	}
	return identityapp.NewAPIKeyCommands(identityapp.APIKeyCommandConfig{Transactions: apiKeyTransactions{factory}, Credentials: credentials, Authorizer: identityapp.NewAPIKeyWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type apiKeyTransactions struct{ factory app.UnitOfWorkFactory }

func (t apiKeyTransactions) ExecuteAPIKey(ctx context.Context, tenant string, fn func(context.Context, identityapp.APIKeyTransaction) error) error {
	return mapAPIKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Identity.(identityapp.APIKeyWriteReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := reader.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, apiKeyTransaction{repos.Identity, repos.Audit})
	}))
}

type apiKeyTransaction struct {
	identity interface {
		InsertAPIKey(context.Context, domain.APIKey) error
	}
	audit app.AuditRepository
}

func (t apiKeyTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewAPIKeyWriteAuthorizer().Authorize(ctx, a, r)
}
func (t apiKeyTransaction) InsertAPIKey(ctx context.Context, key identitydomain.APIKey) error {
	return mapAPIKeyWriteError(t.identity.InsertAPIKey(ctx, domain.APIKey(key)))
}
func (t apiKeyTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapAPIKeyWriteError(err)
}
func mapAPIKeyWriteError(err error) error {
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
