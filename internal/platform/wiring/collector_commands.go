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
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func BuildCollectorCommands(factory app.UnitOfWorkFactory, pepper string, production bool) (*integrationapp.CollectorCommands, error) {
	if factory == nil {
		return nil, errors.New("collector transactions are required")
	}
	credentials, err := buildAuthenticationCredentials(pepper, production)
	if err != nil {
		return nil, err
	}
	return integrationapp.NewCollectorCommands(integrationapp.CollectorCommandConfig{
		Transactions: collectorTransactions{factory}, Credentials: collectorCredentials{credentials},
		Authorizer: integrationapp.NewCollectorWriteAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID),
	})
}

type collectorCredentials struct {
	credentials *identityapp.HMACAuthenticationCredentials
}

func (c collectorCredentials) GenerateCollectorCredential(ctx context.Context) (integrationapp.CollectorCredential, error) {
	if ctx == nil {
		return integrationapp.CollectorCredential{}, integrationapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return integrationapp.CollectorCredential{}, err
	}
	v, err := c.credentials.Generate()
	return integrationapp.CollectorCredential{Secret: v.Secret, Prefix: v.Prefix, Hash: v.Hash}, err
}

type collectorBuildWrites interface {
	InsertCollector(context.Context, domain.Collector) error
	InsertCollectorRelease(context.Context, domain.CollectorRelease) error
}
type collectorIdentityWrites interface {
	InsertAPIKey(context.Context, domain.APIKey) error
}
type collectorCommercialWrites interface {
	InsertCommercialCollectorDefinition(context.Context, domain.CommercialCollectorDefinition) error
}
type collectorTransactions struct{ factory app.UnitOfWorkFactory }

func (t collectorTransactions) ExecuteCollector(ctx context.Context, fn func(context.Context, integrationapp.CollectorTransaction) error) error {
	return mapSourceRepositoryWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Builds.(integrationapp.CollectorWriteReader)
		if !ok || repos.Identity == nil || repos.Enterprise == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, collectorTransaction{reader, repos.Builds, repos.Identity, repos.Enterprise, repos.Audit})
	}))
}

type collectorTransaction struct {
	reader     integrationapp.CollectorWriteReader
	builds     collectorBuildWrites
	identity   collectorIdentityWrites
	commercial collectorCommercialWrites
	audit      app.AuditRepository
}

func (t collectorTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return integrationapp.NewCollectorWriteAuthorizer().Authorize(ctx, a, r)
}
func (t collectorTransaction) LockCollectorWrites(ctx context.Context, tenant string) error {
	return mapSourceRepositoryWriteError(t.reader.LockCollectorWrites(ctx, tenant))
}
func (t collectorTransaction) CollectorNameExists(ctx context.Context, tenant, name string) (bool, error) {
	v, err := t.reader.CollectorNameExists(ctx, tenant, name)
	return v, mapSourceRepositoryWriteError(err)
}
func (t collectorTransaction) CommercialCollectorIdentityExists(ctx context.Context, tenant, provider, name, version string) (bool, error) {
	v, err := t.reader.CommercialCollectorIdentityExists(ctx, tenant, provider, name, version)
	return v, mapSourceRepositoryWriteError(err)
}
func (t collectorTransaction) ReadCollectorReleaseReference(ctx context.Context, tenant, kind, id string) (integrationapp.CollectorReference, error) {
	v, err := t.reader.ReadCollectorReleaseReference(ctx, tenant, kind, id)
	return v, mapSourceRepositoryWriteError(err)
}
func (t collectorTransaction) InsertCollectorAPIKey(ctx context.Context, v identitydomain.APIKey) error {
	return mapSourceRepositoryWriteError(t.identity.InsertAPIKey(ctx, domain.APIKey(v)))
}
func (t collectorTransaction) InsertCollector(ctx context.Context, v integrationdomain.Collector) error {
	return mapSourceRepositoryWriteError(t.builds.InsertCollector(ctx, domain.CollectorFromContextModel(v)))
}
func (t collectorTransaction) InsertCollectorRelease(ctx context.Context, v integrationdomain.CollectorRelease) error {
	return mapSourceRepositoryWriteError(t.builds.InsertCollectorRelease(ctx, domain.CollectorRelease(v)))
}
func (t collectorTransaction) InsertCommercialCollectorDefinition(ctx context.Context, v integrationdomain.CommercialCollectorDefinition) error {
	return mapSourceRepositoryWriteError(t.commercial.InsertCommercialCollectorDefinition(ctx, domain.CommercialCollectorDefinition(v)))
}
func (t collectorTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, v)
	return r, mapSourceRepositoryWriteError(err)
}
