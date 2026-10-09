package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func TestDeploymentNativeFixtureReadsCurrentRepositoryAndDiscardsFailedCommit(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	env, err := ledger.CreateDeploymentEnvironment(t.Context(), owner.actor, app.CreateEnvironmentInput{ProductID: owner.product.ID, Name: "Production", Kind: "production"})
	if err != nil {
		t.Fatal(err)
	}
	finished := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	want, err := ledger.RecordDeployment(t.Context(), owner.actor, app.RecordDeploymentInput{EnvironmentID: env.ID, ReleaseID: owner.release.ID, Status: "succeeded", StartedAt: finished.Add(-time.Hour), FinishedAt: &finished})
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("deployment read used aggregate clock") }})
	query := deploymentQueryFixture{catalogFixtureCommands{ledger: rebound}}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"deployment:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "release", ResourceID: owner.release.ID, Scopes: []string{"deployment:read"}}}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := query.GetDeployment(t.Context(), human, want.ID)
	if err != nil || !reflect.DeepEqual(v, operationsdomain.DeploymentEvent(want)) {
		t.Fatal("rebound point used cached ownership or lost public fields", err)
	}
	*v.FinishedAt = v.FinishedAt.Add(time.Hour)
	again, err := query.GetDeployment(t.Context(), human, want.ID)
	if err != nil || !reflect.DeepEqual(again, operationsdomain.DeploymentEvent(want)) {
		t.Fatal("returned timestamp changed stored deployment", err)
	}
	human.ResourceGrants = nil
	if v, err := query.GetDeployment(t.Context(), human, want.ID); !errors.Is(err, app.ErrForbidden) || !reflect.DeepEqual(v, operationsdomain.DeploymentEvent{}) {
		t.Fatal("revoked grant disclosed deployment", err)
	}
	factory.fail = true
	rollbacks := factory.rollbacks
	if v, err := query.GetDeployment(t.Context(), owner.actor, want.ID); err == nil || !reflect.DeepEqual(v, operationsdomain.DeploymentEvent{}) || factory.rollbacks != rollbacks+1 {
		t.Fatal("failed read commit exposed deployment or missed rollback", err)
	}
	server, err := newLegacyServerFixture(rebound)
	if err != nil {
		t.Fatal(err)
	}
	server.authn = &configuredAuthenticator{actor: owner.actor}
	path := "/v1/deployments/" + want.ID
	response := getRaw(t, server, "fixture", path, 500).Body.String()
	var problem map[string]any
	if err := json.Unmarshal([]byte(response), &problem); err != nil {
		t.Fatal(err)
	}
	if problem["instance"] != path || problem["data"] != nil || strings.Contains(response, "private-query") || strings.Contains(response, want.EvidenceID) || strings.Contains(response, `"release_id"`) {
		t.Fatal("failed HTTP read leaked internal errors or deployment fields")
	}
	factory.fail = false
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read/denial/failed commit changed repository state", err)
	}
}

func TestDeploymentNativeFixtureRequiresRepositoriesAndPreservesExplicitPort(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	query := deploymentQueryFixture{catalogFixtureCommands{ledger: ledger}}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:read"}}
	if v, err := query.GetDeployment(t.Context(), a, "deployment"); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, operationsdomain.DeploymentEvent{}) {
		t.Fatal("missing repository restored cached read", err)
	}
	a.Scopes = nil
	if _, err := query.GetDeployment(t.Context(), a, "deployment"); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("missing authority reached storage", err)
	}
	a.Scopes = []string{"deployment:read"}
	var missingContext context.Context
	if _, err := query.GetDeployment(missingContext, a, "deployment"); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := query.GetDeployment(ctx, a, "deployment"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not propagated", err)
	}
	explicit := &deploymentPointQueryFake{}
	s := &Server{deploymentPointQuery: explicit}
	s.bindDeploymentFixturePorts(ledger)
	if s.deploymentPointQuery != explicit {
		t.Fatal("rebind replaced explicit focused point query")
	}
}
