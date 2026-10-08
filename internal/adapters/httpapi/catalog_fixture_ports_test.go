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

// Only existing local test setup uses these adapters. Production transport has
// no aggregate fallback for catalog writes. The scoped clone preserves the
// fixture's real transaction/replay algorithm until the aggregate is deleted.
type catalogFixtureCommandContextKey struct{}

type catalogFixtureCommands struct{ ledger *app.Ledger }

func (f catalogFixtureCommands) commandLedger(ctx context.Context) *app.Ledger {
	if ledger, ok := ctx.Value(catalogFixtureCommandContextKey{}).(*app.Ledger); ok {
		return ledger
	}
	return f.ledger
}

func (f catalogFixtureCommands) AuthorizeProductCreation(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateProductInput) error {
	return f.commandLedger(ctx).AuthorizeProductCreation(ctx, actor, input)
}

func (f catalogFixtureCommands) CreateProduct(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateProductInput) (releasedomain.Product, error) {
	value, err := f.commandLedger(ctx).CreateProduct(ctx, actor, input.Name, input.Slug)
	return releasedomain.Product{ID: value.ID, TenantID: value.TenantID, Name: value.Name, Slug: value.Slug, CreatedAt: value.CreatedAt}, err
}

func (f catalogFixtureCommands) AuthorizeProjectCreation(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateProjectInput) error {
	return f.commandLedger(ctx).AuthorizeProjectCreation(ctx, actor, input)
}

func (f catalogFixtureCommands) CreateProject(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateProjectInput) (releasedomain.Project, error) {
	value, err := f.commandLedger(ctx).CreateProject(ctx, actor, input.ProductID, input.Name)
	return releasedomain.Project{ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, Name: value.Name, CreatedAt: value.CreatedAt}, err
}

func (f catalogFixtureCommands) AuthorizeReleaseCreation(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateReleaseInput) error {
	return f.commandLedger(ctx).AuthorizeReleaseCreation(ctx, actor, input)
}

func (f catalogFixtureCommands) CreateRelease(ctx context.Context, actor identitydomain.Actor, input releaseapp.CreateReleaseInput) (releasedomain.Release, error) {
	value, err := f.commandLedger(ctx).CreateRelease(ctx, actor, input.ProductID, input.Version)
	if err != nil {
		return releasedomain.Release{}, err
	}
	return releaseFixtureModel(value)
}

type catalogFixtureReplayExecutor struct{ ledger *app.Ledger }

func (e catalogFixtureReplayExecutor) WithBodyDigest(ctx context.Context, actor domain.Actor, method, path, key, digest string, authorize func(context.Context) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if e.ledger == nil || authorize == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	if err := authorize(ctx); err != nil {
		return 0, nil, err
	}
	return e.ledger.WithIdempotencyRequestHash(ctx, actor, method, path, key, digest, func(commandCtx context.Context, commandLedger *app.Ledger) (int, any, error) {
		return run(context.WithValue(commandCtx, catalogFixtureCommandContextKey{}, commandLedger))
	})
}

func (e catalogFixtureReplayExecutor) WithBody(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, authorize func(context.Context) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if e.ledger == nil || authorize == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	if err := authorize(ctx); err != nil {
		return 0, nil, err
	}
	return e.ledger.WithIdempotency(ctx, actor, method, path, key, body, func(commandCtx context.Context, commandLedger *app.Ledger) (int, any, error) {
		return run(context.WithValue(commandCtx, catalogFixtureCommandContextKey{}, commandLedger))
	})
}

// Preserve the legacy fixture's response guard, including on saved responses.
// This post-execution guard is test-only, not a SQL ownership-locking proof.
// Production replay authorization runs inside its focused durable transaction.
func (e catalogFixtureReplayExecutor) WithBodyReplayAuthorization(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, authorize func(context.Context) error, authorizeReplay func(context.Context, any) error, run func(context.Context) (int, any, error)) (int, any, error) {
	if authorizeReplay == nil {
		return 0, nil, app.ErrValidation
	}
	status, response, err := e.WithBody(ctx, actor, method, path, key, body, authorize, run)
	if err != nil {
		return 0, nil, err
	}
	if err := authorizeReplay(ctx, response); err != nil {
		return 0, nil, err
	}
	return status, response, nil
}

func (s *Server) bindCatalogFixturePorts(ledger *app.Ledger) {
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
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Fixture", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
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
