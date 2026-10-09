package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func BuildSourceRepositoryCommands(factory app.UnitOfWorkFactory) (*integrationapp.SourceRepositoryCommands, error) {
	if factory == nil {
		return nil, errors.New("source repository transactions are required")
	}
	return integrationapp.NewSourceRepositoryCommands(integrationapp.SourceRepositoryCreationConfig{Transactions: sourceRepositoryTransactions{factory}, Authorizer: integrationquery.NewSourceWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type sourceRepositoryTransactions struct{ factory app.UnitOfWorkFactory }

func (t sourceRepositoryTransactions) ExecuteSourceRepository(ctx context.Context, fn func(context.Context, integrationapp.SourceRepositoryCreationTransaction) error) error {
	return mapSourceRepositoryWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Source.(integrationapp.SourceRepositoryCreationReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, sourceRepositoryTransaction{reader, repos.Source, repos.Audit})
	}))
}

type sourceRepositoryTransaction struct {
	reader integrationapp.SourceRepositoryCreationReader
	source app.SourceRepository
	audit  app.AuditRepository
}

func (t sourceRepositoryTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return integrationquery.NewSourceWriteAuthorizer().Authorize(ctx, a, r)
}
func (t sourceRepositoryTransaction) LockRepositoryCreation(ctx context.Context, tenant string) error {
	return mapSourceRepositoryWriteError(t.reader.LockRepositoryCreation(ctx, tenant))
}
func (t sourceRepositoryTransaction) LockRepositoryProject(ctx context.Context, tenant, id string) (integrationapp.SourceProjectIdentity, error) {
	p, err := t.reader.LockRepositoryProject(ctx, tenant, id)
	return p, mapSourceRepositoryWriteError(err)
}
func (t sourceRepositoryTransaction) RepositoryIdentityByName(ctx context.Context, tenant, provider, name string) (integrationapp.SourceRepositoryIdentity, bool, error) {
	p, found, err := t.reader.RepositoryIdentityByName(ctx, tenant, provider, name)
	return p, found, mapSourceRepositoryWriteError(err)
}
func (t sourceRepositoryTransaction) ReadSourceRepository(ctx context.Context, tenant, id string) (integrationdomain.SourceRepository, error) {
	v, err := t.reader.ReadSourceRepository(ctx, tenant, id)
	return v, mapSourceRepositoryWriteError(err)
}
func (t sourceRepositoryTransaction) InsertSourceRepository(ctx context.Context, v integrationdomain.SourceRepository) error {
	return mapSourceRepositoryWriteError(t.source.InsertSourceRepository(ctx, domain.SourceRepository{ID: v.ID, TenantID: v.TenantID, ProjectID: v.ProjectID, Provider: v.Provider, FullName: v.FullName, CloneURL: v.CloneURL, DefaultBranch: v.DefaultBranch, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (t sourceRepositoryTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapSourceRepositoryWriteError(err)
}
func mapSourceRepositoryWriteError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return integrationapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return integrationapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return integrationapp.ErrConflict
	default:
		return err
	}
}
