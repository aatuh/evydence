package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type commercialCollectorFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type commercialCollectorFixtureTransaction struct {
	collectorReleaseFixtureTransaction
	reader integrationapp.CollectorWriteReader
}

func (f commercialCollectorFixtureTransactions) ExecuteCollector(ctx context.Context, run func(context.Context, integrationapp.CollectorTransaction) error) error {
	if ctx == nil || run == nil {
		return integrationapp.ErrValidation
	}
	return collectorReleaseFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Builds.(integrationapp.CollectorWriteReader)
		if !ok || r.Enterprise == nil || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, commercialCollectorFixtureTransaction{collectorReleaseFixtureTransaction{reader, r, f.readOnly}, reader})
	}))
}
func (t commercialCollectorFixtureTransaction) CommercialCollectorIdentityExists(ctx context.Context, tenant, provider, name, version string) (bool, error) {
	if t.readOnly {
		panic("commercial preflight read uniqueness metadata")
	}
	v, err := t.reader.CommercialCollectorIdentityExists(ctx, tenant, provider, name, version)
	return v, collectorReleaseFixtureCoreError(err)
}
func (t commercialCollectorFixtureTransaction) InsertCommercialCollectorDefinition(ctx context.Context, v integrationdomain.CommercialCollectorDefinition) error {
	if t.readOnly {
		panic("commercial preflight inserted definition")
	}
	return collectorReleaseFixtureCoreError(t.repos.Enterprise.InsertCommercialCollectorDefinition(ctx, domain.CommercialCollectorDefinition(v)))
}
func (commercialCollectorFixtureTransaction) InsertCollectorRelease(context.Context, integrationdomain.CollectorRelease) error {
	panic("commercial definition command wrote release")
}
func (commercialCollectorFixtureTransaction) ReadCollectorReleaseReference(context.Context, string, string, string) (integrationapp.CollectorReference, error) {
	panic("commercial definition command read release references")
}

func (f integrationFixtureCommands) nativeCommercialCollector(readOnly bool) (*integrationapp.CollectorCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return integrationapp.NewCollectorCommands(integrationapp.CollectorCommandConfig{Transactions: commercialCollectorFixtureTransactions{f.catalogFixtureCommands, readOnly}, Credentials: collectorReleaseNoCredentials{}, Authorizer: integrationapp.NewCollectorWriteAuthorizer(), Clock: clock, IDs: ids})
}

var _ integrationapp.CollectorTransaction = commercialCollectorFixtureTransaction{}
