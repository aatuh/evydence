package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type collectorCreationFixtureCredentials struct{ credentials identityapp.APIKeyCredentials }

func (c collectorCreationFixtureCredentials) GenerateCollectorCredential(ctx context.Context) (integrationapp.CollectorCredential, error) {
	if ctx == nil || c.credentials == nil {
		return integrationapp.CollectorCredential{}, integrationapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return integrationapp.CollectorCredential{}, err
	}
	v, err := c.credentials.Generate()
	return integrationapp.CollectorCredential{Secret: v.Secret, Prefix: v.Prefix, Hash: v.Hash}, err
}

type collectorCreationFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type collectorCreationFixtureTransaction struct {
	collectorReleaseFixtureTransaction
	reader integrationapp.CollectorWriteReader
}

func (f collectorCreationFixtureTransactions) ExecuteCollector(ctx context.Context, run func(context.Context, integrationapp.CollectorTransaction) error) error {
	if ctx == nil || run == nil {
		return integrationapp.ErrValidation
	}
	return collectorReleaseFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Builds.(integrationapp.CollectorWriteReader)
		if !ok || r.Identity == nil || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, collectorCreationFixtureTransaction{collectorReleaseFixtureTransaction{reader, r, f.readOnly}, reader})
	}))
}
func (t collectorCreationFixtureTransaction) CollectorNameExists(ctx context.Context, tenant, name string) (bool, error) {
	if t.readOnly {
		panic("collector creation preflight read uniqueness metadata")
	}
	v, err := t.reader.CollectorNameExists(ctx, tenant, name)
	return v, collectorReleaseFixtureCoreError(err)
}
func (t collectorCreationFixtureTransaction) InsertCollectorAPIKey(ctx context.Context, v identitydomain.APIKey) error {
	if t.readOnly {
		panic("collector creation preflight inserted credential")
	}
	return collectorReleaseFixtureCoreError(t.repos.Identity.InsertAPIKey(ctx, domain.APIKey(v)))
}
func (t collectorCreationFixtureTransaction) InsertCollector(ctx context.Context, v integrationdomain.Collector) error {
	if t.readOnly {
		panic("collector creation preflight inserted collector")
	}
	return collectorReleaseFixtureCoreError(t.repos.Builds.InsertCollector(ctx, domain.CollectorFromContextModel(v)))
}
func (collectorCreationFixtureTransaction) InsertCollectorRelease(context.Context, integrationdomain.CollectorRelease) error {
	panic("collector creation wrote release")
}
func (collectorCreationFixtureTransaction) ReadCollectorReleaseReference(context.Context, string, string, string) (integrationapp.CollectorReference, error) {
	panic("collector creation read release reference")
}

func (f integrationFixtureCommands) nativeCollectorCreation(readOnly bool) (*integrationapp.CollectorCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	credentials := f.credentials
	if readOnly {
		credentials = collectorReleaseNoCredentials{}
	} else {
		if credentials == nil {
			credentials = collectorCreationFixtureCredentials{fixtureSessionCredentials("test")}
		}
		if f.clock != nil {
			clock = f.clock
		}
	}
	return integrationapp.NewCollectorCommands(integrationapp.CollectorCommandConfig{Transactions: collectorCreationFixtureTransactions{f.catalogFixtureCommands, readOnly}, Credentials: credentials, Authorizer: integrationapp.NewCollectorWriteAuthorizer(), Clock: clock, IDs: ids})
}

// Per-fixture dependencies only; never inspect Ledger configuration or publish
// issued credentials into aggregate caches. Explicit authentication is preserved.
func (s *Server) bindCollectorFixtureResources(pepper string, clock application.Clock) {
	if f, ok := s.collectorCommands.(integrationFixtureCommands); ok {
		f.credentials, f.clock = collectorCreationFixtureCredentials{fixtureSessionCredentials(pepper)}, clock
		s.collectorCommands = f
	}
	switch f := s.authn.(type) {
	case identityNativeFixtureAuthenticator:
		s.authn = fixtureIdentityAuthenticator(f.ledger, pepper, clock)
	case ssoFixtureAuthenticator:
		s.authn = fixtureIdentityAuthenticator(f.ledger, pepper, clock)
	case *app.Ledger:
		s.authn = fixtureIdentityAuthenticator(f, pepper, clock)
	}
}

var _ integrationapp.CollectorTransaction = collectorCreationFixtureTransaction{}
