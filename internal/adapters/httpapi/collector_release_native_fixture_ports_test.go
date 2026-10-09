package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type collectorReleaseFixtureReader interface {
	LockCollectorWrites(context.Context, string) error
	ReadCollectorReleaseReference(context.Context, string, string, string) (integrationapp.CollectorReference, error)
}
type collectorReleaseFixtureTransactions struct{ catalogFixtureCommands }
type collectorReleaseFixtureTransaction struct {
	collectorReleaseFixtureReader
	repos app.Repositories
}

func (f collectorReleaseFixtureTransactions) ExecuteCollector(ctx context.Context, run func(context.Context, integrationapp.CollectorTransaction) error) error {
	if ctx == nil || run == nil {
		return integrationapp.ErrValidation
	}
	return collectorReleaseFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Builds.(collectorReleaseFixtureReader)
		if !ok || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, collectorReleaseFixtureTransaction{reader, r})
	}))
}
func (t collectorReleaseFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return integrationapp.NewCollectorWriteAuthorizer().Authorize(ctx, a, r)
}
func (t collectorReleaseFixtureTransaction) CollectorNameExists(context.Context, string, string) (bool, error) {
	panic("release command checked collector name")
}
func (t collectorReleaseFixtureTransaction) CommercialCollectorIdentityExists(context.Context, string, string, string, string) (bool, error) {
	panic("release command checked commercial uniqueness")
}
func (t collectorReleaseFixtureTransaction) InsertCollectorAPIKey(context.Context, identitydomain.APIKey) error {
	panic("release command issued credentials")
}
func (t collectorReleaseFixtureTransaction) InsertCollector(context.Context, integrationdomain.Collector) error {
	panic("release command inserted collector")
}
func (t collectorReleaseFixtureTransaction) InsertCommercialCollectorDefinition(context.Context, integrationdomain.CommercialCollectorDefinition) error {
	panic("release command inserted commercial collector")
}
func (t collectorReleaseFixtureTransaction) InsertCollectorRelease(ctx context.Context, v integrationdomain.CollectorRelease) error {
	return collectorReleaseFixtureCoreError(t.repos.Builds.InsertCollectorRelease(ctx, domain.CollectorRelease(v)))
}
func (t collectorReleaseFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := (governanceFixtureTransaction{audit: t.repos.Audit}).AppendAudit(ctx, e)
	return v, collectorReleaseFixtureCoreError(err)
}

type collectorReleaseNoCredentials struct{}

func (collectorReleaseNoCredentials) GenerateCollectorCredential(context.Context) (integrationapp.CollectorCredential, error) {
	panic("release command generated credentials")
}
func collectorReleaseFixtureCoreError(err error) error {
	switch {
	case errors.Is(err, app.ErrNotFound):
		return integrationapp.ErrNotFound
	case errors.Is(err, app.ErrValidation):
		return integrationapp.ErrValidation
	case errors.Is(err, app.ErrConflict):
		return integrationapp.ErrConflict
	default:
		return err
	}
}
func collectorReleaseFixtureError(err error) error {
	switch {
	case errors.Is(err, integrationapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, integrationapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, integrationapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
func (f integrationFixtureCommands) nativeCollectorRelease() (*integrationapp.CollectorCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	return integrationapp.NewCollectorCommands(integrationapp.CollectorCommandConfig{Transactions: collectorReleaseFixtureTransactions(f), Credentials: collectorReleaseNoCredentials{}, Authorizer: integrationapp.NewCollectorWriteAuthorizer(), Clock: clock, IDs: ids})
}

var _ integrationapp.CollectorTransaction = collectorReleaseFixtureTransaction{}
