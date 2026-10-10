package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// Test-only composition uses focused services and the real native transaction
// and replay algorithm. The scoped locator carries no aggregate cache.
type catalogFixtureCommandContextKey struct{}

type catalogFixtureCommands struct{ ledger *repositoryFixture }

func (f catalogFixtureCommands) commandLedger(ctx context.Context) *repositoryFixture {
	if ledger, ok := ctx.Value(catalogFixtureCommandContextKey{}).(*repositoryFixture); ok {
		return ledger
	}
	return f.ledger
}

func (f catalogFixtureCommands) AuthorizeProductCreation(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateProductInput) error {
	c, err := f.nativeProduct(true)
	if err != nil {
		return err
	}
	return mapBuildAttestationCommandError(c.AuthorizeProductCreation(ctx, actor, input))
}

func (f catalogFixtureCommands) CreateProduct(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateProductInput) (releasedomain.Product, error) {
	c, err := f.nativeProduct(false)
	if err != nil {
		return releasedomain.Product{}, err
	}
	value, err := c.CreateProduct(ctx, actor, input)
	return value, mapBuildAttestationCommandError(err)
}

func (f catalogFixtureCommands) AuthorizeProjectCreation(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateProjectInput) error {
	c, err := f.nativeProject(true)
	if err != nil {
		return err
	}
	return mapBuildAttestationCommandError(c.AuthorizeProjectCreation(ctx, actor, input))
}

func (f catalogFixtureCommands) CreateProject(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateProjectInput) (releasedomain.Project, error) {
	c, err := f.nativeProject(false)
	if err != nil {
		return releasedomain.Project{}, err
	}
	value, err := c.CreateProject(ctx, actor, input)
	return value, mapBuildAttestationCommandError(err)
}

func (f catalogFixtureCommands) AuthorizeReleaseCreation(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateReleaseInput) error {
	c, err := f.nativeRelease(true)
	if err != nil {
		return err
	}
	return mapBuildAttestationCommandError(c.AuthorizeReleaseCreation(ctx, actor, input))
}

func (f catalogFixtureCommands) CreateRelease(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateReleaseInput) (releasedomain.Release, error) {
	c, err := f.nativeRelease(false)
	if err != nil {
		return releasedomain.Release{}, err
	}
	value, err := c.CreateRelease(ctx, actor, input)
	return value, mapBuildAttestationCommandError(err)
}

type catalogFixtureReplayExecutor struct{ ledger *repositoryFixture }

func (e catalogFixtureReplayExecutor) WithBodyDigest(ctx context.Context, actor domain.Actor, method, path, key, digest string, authorize func(context.Context) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if e.ledger == nil || authorize == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	x := e.nativeReplay(authorize, nil)
	return x.WithBodyDigest(ctx, actor, method, path, key, digest, func(ctx context.Context, _ app.Repositories) (int, any, error) {
		ctx, _ = e.ledger.commandContext(ctx)
		return run(ctx)
	})
}

func (e catalogFixtureReplayExecutor) WithBody(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, authorize func(context.Context) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if e.ledger == nil || authorize == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	x := e.nativeReplay(authorize, nil)
	return x.WithBody(ctx, actor, method, path, key, body, func(ctx context.Context, _ app.Repositories) (int, any, error) {
		ctx, _ = e.ledger.commandContext(ctx)
		return run(ctx)
	})
}

// Preserve response authorization on first delivery and saved selections, now
// inside the real caller-owned transaction rather than after cache publication.
func (e catalogFixtureReplayExecutor) WithBodyReplayAuthorization(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, authorize func(context.Context) error, authorizeReplay func(context.Context, any) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if e.ledger == nil || authorize == nil || authorizeReplay == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	x := e.nativeReplay(authorize, authorizeReplay)
	return x.WithBody(ctx, actor, method, path, key, body, func(ctx context.Context, _ app.Repositories) (int, any, error) {
		ctx, _ = e.ledger.commandContext(ctx)
		status, response, err := run(ctx)
		if err == nil {
			err = authorizeReplay(ctx, response)
		}
		return status, response, err
	})
}

func (e catalogFixtureReplayExecutor) nativeReplay(authorize func(context.Context) error, authorizeReplay func(context.Context, any) error) app.IdempotencyUnitOfWork {
	x := app.IdempotencyUnitOfWork{Transactions: e.ledger.transactions, Now: e.ledger.now, Authorize: func(ctx context.Context, _ app.Repositories) error {
		ctx, _ = e.ledger.commandContext(ctx)
		return authorize(ctx)
	}}
	if authorizeReplay != nil {
		x.AuthorizeReplay = func(ctx context.Context, _ app.Repositories, response any) error {
			ctx, _ = e.ledger.commandContext(ctx)
			return authorizeReplay(ctx, response)
		}
	}
	return x
}

func (s *Server) bindCatalogFixturePorts(ledger *repositoryFixture) {
	commands := catalogFixtureCommands{ledger: ledger}
	if _, fixture := s.productCommands.(catalogFixtureCommands); s.productCommands == nil || fixture {
		s.productCommands = commands
	}
	if _, fixture := s.projectCommands.(catalogFixtureCommands); s.projectCommands == nil || fixture {
		s.projectCommands = commands
	}
	if _, fixture := s.releaseCreationCommands.(catalogFixtureCommands); s.releaseCreationCommands == nil || fixture {
		s.releaseCreationCommands = commands
	}
	if _, fixture := s.durableCommandExecutor.(catalogFixtureReplayExecutor); s.durableCommandExecutor == nil || fixture {
		s.durableCommandExecutor = catalogFixtureReplayExecutor{ledger: ledger}
	}
}

var (
	_ ProductCommands                = catalogFixtureCommands{}
	_ ProjectCommands                = catalogFixtureCommands{}
	_ ReleaseCreationCommands        = catalogFixtureCommands{}
	_ DurableCommandExecutor         = catalogFixtureReplayExecutor{}
	_ DurableStreamedCommandExecutor = catalogFixtureReplayExecutor{}
	_ DurableReplayCommandExecutor   = catalogFixtureReplayExecutor{}
)

type failingCatalogFixtureProduct struct {
	catalogFixtureCommands
	createdID string
	isolated  bool
}

func (f *failingCatalogFixtureProduct) CreateProduct(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateProductInput) (releasedomain.Product, error) {
	f.isolated = f.commandLedger(ctx) != f.ledger
	value, err := f.catalogFixtureCommands.CreateProduct(ctx, actor, input)
	if err != nil {
		return value, err
	}
	f.createdID = value.ID
	return value, errors.New("private fixture failure after catalog write")
}

func TestCatalogFixtureReplayKeepsFailedWritesInsideTheCommandClone(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	clock := providerVerificationFixtureClock()
	bootstrap := tenantBootstrapNativeFixture{factory, fixtureSessionCredentials("fixture-pepper"), clock}
	_, _, secret, err := bootstrap.BootstrapTenant(t.Context(), "Fixture", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	auth := fixtureIdentityAuthenticator(ledger, "fixture-pepper", clock)
	actor, err := auth.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	commands := &failingCatalogFixtureProduct{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	server.productCommands = commands
	body := postRaw(t, server, secret, "/v1/products", "fixture-rollback", []byte(`{"name":"Rolled back","slug":"rollback"}`), 500)
	if commands.createdID == "" || !commands.isolated || strings.Contains(body, "private fixture") || strings.Contains(body, commands.createdID) {
		t.Fatal("failed fixture command bypassed the clone or exposed its partial result")
	}
	products, err := server.productQuery.ListProductsPage(t.Context(), actor, appquery.PageRequest{PageSize: 50, Sort: appquery.SortID, Direction: appquery.Ascending}, nil)
	if err != nil || len(products.Items) != 0 {
		t.Fatal("failed fixture command published an authoritative product", products, err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before.Products, after.Products) || !reflect.DeepEqual(before.AuditEntries, after.AuditEntries) {
		t.Fatal("failed fixture command committed product or audit effects", err)
	}
	if len(after.Idempotency) != 1 {
		t.Fatal("failed fixture command lost its replay failure record")
	}
	for _, record := range after.Idempotency {
		if record.State != app.IdempotencyFailed || record.Response != nil || record.Status != 0 {
			t.Fatal("failed fixture replay retained a partial response")
		}
	}
}
