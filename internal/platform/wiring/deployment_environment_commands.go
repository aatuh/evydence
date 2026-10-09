package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func BuildDeploymentEnvironmentCommands(factory app.UnitOfWorkFactory) (*operationsapp.DeploymentEnvironmentCommands, error) {
	if factory == nil {
		return nil, errors.New("environment transactions are required")
	}
	return operationsapp.NewDeploymentEnvironmentCommands(operationsapp.DeploymentEnvironmentConfig{Transactions: environmentTransactions{factory}, Authorizer: operationsquery.NewDeploymentWriteAuthorizer(), Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type environmentTransactions struct{ factory app.UnitOfWorkFactory }

func (t environmentTransactions) ExecuteEnvironment(ctx context.Context, fn func(context.Context, operationsapp.DeploymentEnvironmentTransaction) error) error {
	return mapEnvironmentWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Deployments.(operationsapp.DeploymentEnvironmentReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, environmentTransaction{reader, repos.Deployments, repos.Audit})
	}))
}

type environmentTransaction struct {
	reader      operationsapp.DeploymentEnvironmentReader
	deployments app.DeploymentRepository
	audit       app.AuditRepository
}

func (t environmentTransaction) LockDeploymentTenant(ctx context.Context, tenant string) error {
	r, ok := t.reader.(operationsapp.DeploymentTenantLocker)
	if !ok {
		return operationsapp.ErrValidation
	}
	return mapEnvironmentWriteError(r.LockDeploymentTenant(ctx, tenant))
}

func (t environmentTransaction) LockEnvironmentProduct(ctx context.Context, tenant, id string) (operationsapp.EnvironmentProduct, error) {
	p, err := t.reader.LockEnvironmentProduct(ctx, tenant, id)
	return p, mapEnvironmentWriteError(err)
}
func (t environmentTransaction) EnvironmentByName(ctx context.Context, tenant, product, name string) (operationsdomain.DeploymentEnvironment, bool, error) {
	v, found, err := t.reader.EnvironmentByName(ctx, tenant, product, name)
	return v, found, mapEnvironmentWriteError(err)
}
func (t environmentTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return operationsquery.NewDeploymentWriteAuthorizer().Authorize(ctx, a, r)
}
func (t environmentTransaction) InsertEnvironment(ctx context.Context, v operationsdomain.DeploymentEnvironment) error {
	return mapEnvironmentWriteError(t.deployments.InsertDeploymentEnvironment(ctx, domain.DeploymentEnvironment{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, Name: v.Name, Kind: v.Kind, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
func (t environmentTransaction) AppendAudit(ctx context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, a)
	return r, mapEnvironmentWriteError(err)
}
func mapEnvironmentWriteError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return operationsapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return operationsapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return operationsapp.ErrConflict
	default:
		return err
	}
}
