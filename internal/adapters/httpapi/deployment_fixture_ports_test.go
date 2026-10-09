package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

// Existing HTTP fixtures use real ownership guards and the isolated replay
// clone. These adapters cannot be built into a production runtime.
type deploymentFixtureCommands struct{ catalogFixtureCommands }

func (f deploymentFixtureCommands) AuthorizeEnvironmentCreation(ctx context.Context, actor identitydomain.Actor, input operationsapp.CreateEnvironmentInput) error {
	return f.commandLedger(ctx).AuthorizeEnvironmentCreation(ctx, actor, input)
}
func (f deploymentFixtureCommands) AuthorizeDeploymentRecording(ctx context.Context, actor identitydomain.Actor, input operationsapp.RecordDeploymentInput) error {
	return f.commandLedger(ctx).AuthorizeDeploymentRecording(ctx, actor, input)
}
func (f deploymentFixtureCommands) CreateDeploymentEnvironment(ctx context.Context, actor identitydomain.Actor, input operationsapp.CreateEnvironmentInput) (operationsdomain.DeploymentEnvironment, error) {
	value, err := f.commandLedger(ctx).CreateDeploymentEnvironment(ctx, actor, app.CreateEnvironmentInput{ProductID: input.ProductID, Name: input.Name, Kind: input.Kind})
	return operationsdomain.DeploymentEnvironment(value), err
}
func (f deploymentFixtureCommands) RecordDeployment(ctx context.Context, actor identitydomain.Actor, input operationsapp.RecordDeploymentInput) (operationsdomain.DeploymentEvent, error) {
	value, err := f.commandLedger(ctx).RecordDeployment(ctx, actor, app.RecordDeploymentInput{EnvironmentID: input.EnvironmentID, ReleaseID: input.ReleaseID, ArtifactIDs: input.ArtifactIDs, Status: input.Status, StartedAt: input.StartedAt, FinishedAt: input.FinishedAt, RollbackOf: input.RollbackOf})
	return operationsdomain.DeploymentEvent(value), err
}

// Fixture queries retain actual tenant/grant checks and shared cursor ordering.
// Unlike these test-only readers, runtime pages are bounded SQL projections.
type deploymentQueryFixture struct{ catalogFixtureCommands }

func (f deploymentQueryFixture) ListEnvironmentsPage(ctx context.Context, actor domain.Actor, product string, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[operationsdomain.DeploymentEnvironment], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, err
	}
	values, err := f.commandLedger(ctx).ListDeploymentEnvironments(ctx, actor, product)
	if err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, err
	}
	items := make([]operationsdomain.DeploymentEnvironment, 0, len(values))
	for _, value := range values {
		items = append(items, operationsdomain.DeploymentEnvironment(value))
	}
	return appquery.Page(items, request, after, func(value operationsdomain.DeploymentEnvironment, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(value.ID, value.CreatedAt, sort)
	})
}
func (f deploymentQueryFixture) ListDeploymentsPage(ctx context.Context, actor domain.Actor, release, environment string, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[operationsdomain.DeploymentEvent], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[operationsdomain.DeploymentEvent]{}, err
	}
	values, err := f.commandLedger(ctx).ListDeployments(ctx, actor, release, environment)
	if err != nil {
		return appquery.Result[operationsdomain.DeploymentEvent]{}, err
	}
	items := make([]operationsdomain.DeploymentEvent, 0, len(values))
	for _, value := range values {
		items = append(items, operationsdomain.DeploymentEvent(value))
	}
	return appquery.Page(items, request, after, func(value operationsdomain.DeploymentEvent, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(value.ID, value.CreatedAt, sort)
	})
}
func (f deploymentQueryFixture) GetDeployment(ctx context.Context, actor domain.Actor, id string) (operationsdomain.DeploymentEvent, error) {
	value, err := f.commandLedger(ctx).GetDeployment(ctx, actor, id)
	return operationsdomain.DeploymentEvent(value), err
}

func (s *Server) bindDeploymentFixturePorts(ledger *app.Ledger) {
	commands := deploymentFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.deploymentEnvironmentCommands.(deploymentFixtureCommands); s.deploymentEnvironmentCommands == nil || fixture {
		s.deploymentEnvironmentCommands = commands
	}
	if _, fixture := s.deploymentCommands.(deploymentFixtureCommands); s.deploymentCommands == nil || fixture {
		s.deploymentCommands = commands
	}
	query := deploymentQueryFixture{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.deploymentListQuery.(deploymentQueryFixture); s.deploymentListQuery == nil || fixture {
		s.deploymentListQuery = query
	}
	if _, fixture := s.deploymentPointQuery.(deploymentQueryFixture); s.deploymentPointQuery == nil || fixture {
		s.deploymentPointQuery = query
	}
}

var (
	_ DeploymentEnvironmentCommands = deploymentFixtureCommands{}
	_ DeploymentCommands            = deploymentFixtureCommands{}
	_ DeploymentListQuery           = deploymentQueryFixture{}
	_ DeploymentPointQuery          = deploymentQueryFixture{}
)

type failingDeploymentFixtureCommand struct {
	deploymentFixtureCommands
	createdID string
	isolated  bool
}

func (f *failingDeploymentFixtureCommand) CreateDeploymentEnvironment(ctx context.Context, actor identitydomain.Actor, input operationsapp.CreateEnvironmentInput) (operationsdomain.DeploymentEnvironment, error) {
	f.isolated = f.commandLedger(ctx) != f.ledger
	value, err := f.deploymentFixtureCommands.CreateDeploymentEnvironment(ctx, actor, input)
	if err != nil {
		return value, err
	}
	f.createdID = value.ID
	return value, errors.New("private deployment fixture failure")
}
func (f *failingDeploymentFixtureCommand) RecordDeployment(ctx context.Context, actor identitydomain.Actor, input operationsapp.RecordDeploymentInput) (operationsdomain.DeploymentEvent, error) {
	f.isolated = f.commandLedger(ctx) != f.ledger
	value, err := f.deploymentFixtureCommands.RecordDeployment(ctx, actor, input)
	if err != nil {
		return value, err
	}
	f.createdID = value.ID
	return value, errors.New("private deployment fixture failure")
}

func TestDeploymentFixtureReplayRollsBackAllEffectsAfterWriteFailure(t *testing.T) {
	for _, event := range []bool{false, true} {
		t.Run(fmt.Sprintf("event=%t", event), func(t *testing.T) {
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
			product, err := ledger.CreateProduct(t.Context(), actor, "Fixture", "fixture")
			if err != nil {
				t.Fatal(err)
			}
			path, body := "/v1/environments", fmt.Sprintf(`{"product_id":%q,"name":"Production","kind":"production"}`, product.ID)
			if event {
				release, err := ledger.CreateRelease(t.Context(), actor, product.ID, "1")
				if err != nil {
					t.Fatal(err)
				}
				environment, err := ledger.CreateDeploymentEnvironment(t.Context(), actor, app.CreateEnvironmentInput{ProductID: product.ID, Name: "Production", Kind: "production"})
				if err != nil {
					t.Fatal(err)
				}
				path, body = "/v1/deployments", fmt.Sprintf(`{"environment_id":%q,"release_id":%q,"status":"succeeded"}`, environment.ID, release.ID)
			}
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: actor}
			commands := &failingDeploymentFixtureCommand{deploymentFixtureCommands: deploymentFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.deploymentEnvironmentCommands, server.deploymentCommands = commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, secret, path, "fixture-deployment-failure", []byte(body), 500)
			if commands.createdID == "" || !commands.isolated || strings.Contains(out, commands.createdID) || strings.Contains(out, "private deployment") {
				t.Fatal("failed deployment bypassed isolation or exposed partial effects")
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed deployment lost its replay failure record")
			}
			for _, record := range after.Idempotency {
				if record.State != app.IdempotencyFailed || record.Response != nil || record.Status != 0 {
					t.Fatal("failed deployment retained a partial response")
				}
			}
			// The failed replay record is intentional; every other repository
			// effect, including evidence, audits and outbox work, must roll back.
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed deployment committed repository effects")
			}
			if event {
				if _, err := ledger.GetDeployment(t.Context(), actor, commands.createdID); !errors.Is(err, app.ErrNotFound) {
					t.Fatal("failed deployment was published to fixture reads", err)
				}
			} else {
				values, err := ledger.ListDeploymentEnvironments(t.Context(), actor, product.ID)
				if err != nil || len(values) != 0 {
					t.Fatal("failed environment was published to fixture reads", err)
				}
			}
		})
	}
}

func TestDeploymentQueryFixturesPreserveTenantOwnershipAndReadScope(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper"})
	query := deploymentQueryFixture{catalogFixtureCommands{ledger: ledger}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	var actors []domain.Actor
	var environments []domain.DeploymentEnvironment
	var events []domain.DeploymentEvent
	for _, name := range []string{"Alpha", "Bravo"} {
		_, _, secret, err := ledger.BootstrapTenant(t.Context(), name, "admin", []string{"*"})
		if err != nil {
			t.Fatal(err)
		}
		actor, err := ledger.Authenticate(t.Context(), secret)
		if err != nil {
			t.Fatal(err)
		}
		product, err := ledger.CreateProduct(t.Context(), actor, name, name)
		if err != nil {
			t.Fatal(err)
		}
		release, err := ledger.CreateRelease(t.Context(), actor, product.ID, "1")
		if err != nil {
			t.Fatal(err)
		}
		environment, err := ledger.CreateDeploymentEnvironment(t.Context(), actor, app.CreateEnvironmentInput{ProductID: product.ID, Name: "Production", Kind: "production"})
		if err != nil {
			t.Fatal(err)
		}
		event, err := ledger.RecordDeployment(t.Context(), actor, app.RecordDeploymentInput{EnvironmentID: environment.ID, ReleaseID: release.ID, Status: "succeeded"})
		if err != nil {
			t.Fatal(err)
		}
		actors, environments, events = append(actors, actor), append(environments, environment), append(events, event)
	}
	for i, actor := range actors {
		envs, err := query.ListEnvironmentsPage(t.Context(), actor, environments[i].ProductID, page, nil)
		if err != nil || len(envs.Items) != 1 || envs.Items[0].ID != environments[i].ID || envs.Items[0].TenantID != actor.TenantID || envs.Next != nil {
			t.Fatal("fixture environment page leaked ownership or ignored scope", err)
		}
		deployments, err := query.ListDeploymentsPage(t.Context(), actor, events[i].ReleaseID, environments[i].ID, page, nil)
		if err != nil || len(deployments.Items) != 1 || !reflect.DeepEqual(deployments.Items[0], operationsdomain.DeploymentEvent(events[i])) || deployments.Next != nil {
			t.Fatal("fixture deployment page leaked ownership or changed fields", err)
		}
		if _, err := query.GetDeployment(t.Context(), actor, events[1-i].ID); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("fixture deployment point crossed tenant ownership", err)
		}
		actor.Scopes = []string{"product:read"}
		if _, err := query.ListEnvironmentsPage(t.Context(), actor, "", page, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture environment page skipped read authority", err)
		}
		if _, err := query.ListDeploymentsPage(t.Context(), actor, "", "", page, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture deployment page skipped read authority", err)
		}
		if _, err := query.GetDeployment(t.Context(), actor, events[i].ID); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture deployment point skipped read authority", err)
		}
	}
}
