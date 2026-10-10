package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

type repositoryFixtureStateTrap struct{ loads, saves int }

func (s *repositoryFixtureStateTrap) LoadState(context.Context) (app.PersistedState, bool, error) {
	s.loads++
	return app.PersistedState{}, false, errors.New("private fixture state snapshot must not be loaded")
}
func (s *repositoryFixtureStateTrap) SaveState(context.Context, app.PersistedState) error {
	s.saves++
	return errors.New("private fixture state snapshot must not be saved")
}

func TestRepositoryFixtureConstructionNeverLoadsAggregateState(t *testing.T) {
	store := &repositoryFixtureStateTrap{}
	factory := app.NewMemoryUnitOfWorkFactory()
	fixture, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{UnitOfWork: factory, Store: store})
	if err != nil || fixture == nil || store.loads != 0 || store.saves != 0 {
		t.Fatal("repository-only fixture still constructs or loads an aggregate", err)
	}
	owner := seedEvidenceFixtureScope(t, fixture, "Owner")
	if owner.actor.TenantID == "" || owner.original.ID == "" || store.loads != 0 || store.saves != 0 {
		t.Fatal("native fixture setup consulted a whole-state store")
	}
}

func TestHTTPFixtureConstructorAndReplayDoNotUseAggregate(t *testing.T) {
	for _, path := range []string{"legacy_ledger_fixture_test.go", "catalog_fixture_ports_test.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if selector.Sel.Name == "NewLedgerWithContext" || path == "catalog_fixture_ports_test.go" && (selector.Sel.Name == "WithIdempotency" || selector.Sel.Name == "WithIdempotencyRequestHash") {
				t.Errorf("%s retains aggregate construction or replay", path)
			}
			return true
		})
	}
}

func TestHTTPTestFixturesDoNotReferenceAggregateType(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	inspected := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		inspected++
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Ledger" {
				return true
			}
			if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "app" {
				t.Errorf("%s still requires the production aggregate type", entry.Name())
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no HTTP test fixtures inspected")
	}
}

func TestRepositoryFixtureReplayUsesOneActualTransactionAndCurrentAuthority(t *testing.T) {
	base := app.NewMemoryUnitOfWorkFactory()
	factory := &operatorQueryFailureFactory{base: base}
	store := &repositoryFixtureStateTrap{}
	fixture, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{UnitOfWork: factory, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	owner := seedEvidenceFixtureScope(t, fixture, "Owner")
	commands := catalogFixtureCommands{ledger: fixture}
	executor := catalogFixtureReplayExecutor{ledger: fixture}
	actor := owner.actor
	input := releaseapp.CreateProductInput{Name: "Native transaction", Slug: "native-transaction"}
	runs := 0
	authorize := func(ctx context.Context) error { return commands.AuthorizeProductCreation(ctx, actor, input) }
	run := func(ctx context.Context) (int, any, error) {
		runs++
		scoped := commands.commandLedger(ctx)
		if scoped == fixture || scoped.transactions != factory {
			t.Fatal("command did not receive the actual transaction-only scoped locator")
		}
		value, err := commands.CreateProduct(ctx, actor, input)
		return 201, value, err
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	begins := factory.beginCalls
	status, first, err := executor.WithBody(t.Context(), actor, "POST", "/v1/products", "native-fixture-transaction", []byte(`{"name":"Native transaction"}`), authorize, run)
	if err != nil || status != 201 || runs != 1 || factory.beginCalls != begins+1 {
		t.Fatal("guard and command did not join one actual native replay transaction", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.Products) != len(before.Products)+1 || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID])+1 || len(after.Idempotency) != 1 {
		t.Fatal("native replay lost or duplicated product/audit/response effects", err)
	}
	status, replay, err := executor.WithBody(t.Context(), actor, "POST", "/v1/products", "native-fixture-transaction", []byte(`{"name":"Native transaction"}`), authorize, run)
	if err != nil || status != 201 || runs != 1 || factory.beginCalls != begins+2 {
		t.Fatal("matching replay regenerated data or escaped the guarded transaction", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	replayJSON, err := json.Marshal(replay)
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(firstJSON), string(replayJSON))
	actor.Scopes = []string{"evidence:read"}
	if status, value, err := executor.WithBody(t.Context(), actor, "POST", "/v1/products", "native-fixture-transaction", []byte(`{"name":"Native transaction"}`), authorize, run); !errors.Is(err, app.ErrForbidden) || status != 0 || value != nil || runs != 1 {
		t.Fatal("revoked current authority retrieved a saved response", err)
	}
	unchanged, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, unchanged) || store.loads+store.saves != 0 {
		t.Fatal("replay/denial changed rows or consulted aggregate state", err)
	}
	actor = owner.actor
	factory.fail = true
	if status, value, err := executor.WithBody(t.Context(), actor, "POST", "/v1/products", "native-fixture-commit-failure", []byte(`{"name":"Failure"}`), authorize, func(ctx context.Context) (int, any, error) {
		value, err := commands.CreateProduct(ctx, actor, releaseapp.CreateProductInput{Name: "Failure", Slug: "failure"})
		return 201, value, err
	}); err == nil || status != 0 || value != nil {
		t.Fatal("final commit failure returned partial product data", err)
	}
	unchanged, err = base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, unchanged) {
		t.Fatal("final commit failure published command, audit or replay effects", err)
	}
}

func TestRepositoryFixtureFirstDeliveryResponseGuardRollsBackActualWrites(t *testing.T) {
	base := app.NewMemoryUnitOfWorkFactory()
	fixture := newLegacyLedgerFixture(app.Config{UnitOfWork: base})
	owner := seedEvidenceFixtureScope(t, fixture, "Owner")
	commands := catalogFixtureCommands{ledger: fixture}
	executor := catalogFixtureReplayExecutor{ledger: fixture}
	input := releaseapp.CreateProductInput{Name: "Guarded", Slug: "guarded"}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	guards, writes := 0, 0
	status, response, err := executor.WithBodyReplayAuthorization(t.Context(), owner.actor, "POST", "/v1/products", "guarded-first-delivery", []byte(`{}`),
		func(ctx context.Context) error { return commands.AuthorizeProductCreation(ctx, owner.actor, input) },
		func(context.Context, any) error { guards++; return app.ErrForbidden },
		func(ctx context.Context) (int, any, error) {
			value, err := commands.CreateProduct(ctx, owner.actor, input)
			if err == nil {
				writes++
			}
			return 201, value, err
		})
	if !errors.Is(err, app.ErrForbidden) || status != 0 || response != nil || guards != 1 || writes != 1 {
		t.Fatal("first-delivery response guard skipped actual writes or returned private data", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.Idempotency) != 1 {
		t.Fatal("failed delivery did not retain its safe failure record", err)
	}
	for _, record := range after.Idempotency {
		if record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil {
			t.Fatal("failed response guard stored partial delivery data")
		}
	}
	after.Idempotency = before.Idempotency
	if !reflect.DeepEqual(before, after) {
		t.Fatal("denied first delivery committed product or audit writes")
	}
}

func TestCachedReleaseFixtureHasNoRepositoryOrReplayFallback(t *testing.T) {
	f := newCachedReleaseFixture(t, "Cache canary")
	before, exists, err := f.historicalCache.LoadState(t.Context())
	if err != nil || !exists || before.Tenants[f.scope.actor.TenantID].ID == "" || before.Releases[f.scope.release.ID].ID == "" {
		t.Fatal("missing real historical cache canary", err)
	}
	called := false
	if err := f.ledger.ExecuteUnitOfWork(t.Context(), func(context.Context, app.Repositories) error { called = true; return nil }); !errors.Is(err, app.ErrValidation) || called {
		t.Fatal("missing-repository fixture gained a cache-backed command fallback", err)
	}
	if status, value, err := f.ledger.WithIdempotency(t.Context(), f.scope.actor, "POST", "/v1/products", "no-cache-replay", []byte(`{}`), func(context.Context, *repositoryFixture) (int, any, error) {
		called = true
		return 201, domain.Product{}, nil
	}); !errors.Is(err, app.ErrValidation) || called || status != 0 || value != nil {
		t.Fatal("missing-repository fixture gained an in-memory replay fallback", err)
	}
	after, exists, err := f.historicalCache.LoadState(t.Context())
	if err != nil || !exists || !reflect.DeepEqual(before, after) {
		t.Fatal("failed native fixture command modified the historical cache", err)
	}
}
