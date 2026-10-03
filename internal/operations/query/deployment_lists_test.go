package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type deploymentListReaderStub struct {
	environments appquery.Result[operationsdomain.DeploymentEnvironment]
	deployments  appquery.Result[DeploymentPoint]
	envRequest   EnvironmentPageRequest
	depRequest   DeploymentPageRequest
	envCalls     int
	depCalls     int
}

func (r *deploymentListReaderStub) PageDeploymentEnvironments(_ context.Context, request EnvironmentPageRequest) (appquery.Result[operationsdomain.DeploymentEnvironment], error) {
	r.envRequest, r.envCalls = request, r.envCalls+1
	return r.environments, nil
}

func (r *deploymentListReaderStub) PageDeployments(_ context.Context, request DeploymentPageRequest) (appquery.Result[DeploymentPoint], error) {
	r.depRequest, r.depCalls = request, r.depCalls+1
	return r.deployments, nil
}

func TestDeploymentListsFilterBeforeLimitAndValidateProjection(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	reader := &deploymentListReaderStub{
		environments: appquery.Result[operationsdomain.DeploymentEnvironment]{Items: []operationsdomain.DeploymentEnvironment{{ID: "env_1", TenantID: "ten_1", ProductID: "prod_1", CreatedAt: now}}},
		deployments:  appquery.Result[DeploymentPoint]{Items: []DeploymentPoint{{ProductID: "prod_1", Deployment: operationsdomain.DeploymentEvent{ID: "dep_1", TenantID: "ten_1", EnvironmentID: "env_1", ReleaseID: "rel_1", CreatedAt: now}}}},
	}
	service, err := NewDeploymentLists(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := deploymentActor("product", "prod_1")
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	environments, err := service.ListEnvironmentsPage(t.Context(), actor, "prod_1", page, nil)
	if err != nil || len(environments.Items) != 1 || reader.envCalls != 1 || reader.envRequest.TenantWide || len(reader.envRequest.AllowedProductIDs) != 1 || reader.envRequest.AllowedProductIDs[0] != "prod_1" {
		t.Fatalf("product-scoped environment page=%#v request=%#v error=%v", environments, reader.envRequest, err)
	}
	deployments, err := service.ListDeploymentsPage(t.Context(), actor, "rel_1", "env_1", page, nil)
	if err != nil || len(deployments.Items) != 1 || reader.depCalls != 1 || reader.depRequest.TenantWide || len(reader.depRequest.AllowedProductIDs) != 1 || reader.depRequest.AllowedProductIDs[0] != "prod_1" {
		t.Fatalf("product-scoped deployment page=%#v request=%#v error=%v", deployments, reader.depRequest, err)
	}

	reader.deployments.Items[0].ProductID = "prod_other"
	if _, err := service.ListDeploymentsPage(t.Context(), actor, "rel_1", "env_1", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("wrong-product projection error=%v", err)
	}
	reader.environments.Items[0].TenantID = "ten_other"
	if _, err := service.ListEnvironmentsPage(t.Context(), actor, "prod_1", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign-tenant environment error=%v", err)
	}
	reader.environments.Items[0].TenantID = "ten_1"
	reader.environments.Items[0].ProductID = "prod_other"
	if _, err := service.ListEnvironmentsPage(t.Context(), actor, "", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("wrong-product environment error=%v", err)
	}
	actor.ResourceGrants = nil
	if result, err := service.ListDeploymentsPage(t.Context(), actor, "", "", page, nil); err != nil || len(result.Items) != 0 || reader.depCalls != 2 {
		t.Fatalf("revoked deployment grant left access: %#v error=%v calls=%d", result, err, reader.depCalls)
	}
	if result, err := service.ListEnvironmentsPage(t.Context(), actor, "", page, nil); err != nil || len(result.Items) != 0 || reader.envCalls != 3 {
		t.Fatalf("revoked environment grant left access: %#v error=%v calls=%d", result, err, reader.envCalls)
	}
}

func TestDeploymentListsGrantAndScopeBoundaries(t *testing.T) {
	reader := &deploymentListReaderStub{}
	service, err := NewDeploymentLists(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Descending}
	for _, actor := range []identitydomain.Actor{
		{TenantID: "ten_1", KeyID: "key_1"},
		{TenantID: "ten_1", Scopes: []string{"deployment:read"}},
	} {
		if _, err := service.ListEnvironmentsPage(t.Context(), actor, "", page, nil); err == nil {
			t.Fatalf("missing scope or identity accepted: %#v", actor)
		}
		if _, err := service.ListDeploymentsPage(t.Context(), actor, "", "", page, nil); err == nil {
			t.Fatalf("missing scope or identity accepted: %#v", actor)
		}
	}
	if reader.envCalls != 0 || reader.depCalls != 0 {
		t.Fatalf("unauthorized reads reached storage: environments=%d deployments=%d", reader.envCalls, reader.depCalls)
	}
	releaseActor := deploymentActor("release", "rel_1")
	if result, err := service.ListEnvironmentsPage(t.Context(), releaseActor, "", page, nil); err != nil || len(result.Items) != 0 || reader.envCalls != 0 {
		t.Fatalf("release grant exposed environments: %#v error=%v calls=%d", result, err, reader.envCalls)
	}
	if _, err := service.ListDeploymentsPage(t.Context(), releaseActor, "", "", page, nil); err != nil || reader.depCalls != 1 || len(reader.depRequest.AllowedReleaseIDs) != 1 || reader.depRequest.AllowedReleaseIDs[0] != "rel_1" {
		t.Fatalf("release grant request=%#v error=%v calls=%d", reader.depRequest, err, reader.depCalls)
	}
	projectActor := deploymentActor("project", "proj_1")
	if result, err := service.ListDeploymentsPage(t.Context(), projectActor, "", "", page, nil); err != nil || len(result.Items) != 0 || reader.depCalls != 1 {
		t.Fatalf("project grant exposed deployments: %#v error=%v calls=%d", result, err, reader.depCalls)
	}
	keyActor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"deployment:read"}}
	if _, err := service.ListEnvironmentsPage(t.Context(), keyActor, "", page, nil); err != nil || !reader.envRequest.TenantWide {
		t.Fatalf("key request=%#v error=%v", reader.envRequest, err)
	}
	badPage := page
	badPage.PageSize = 0
	if _, err := service.ListDeploymentsPage(t.Context(), keyActor, "", "", badPage, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid page error=%v", err)
	}
	if _, err := service.ListEnvironmentsPage(t.Context(), keyActor, "", badPage, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid environment page error=%v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.ListDeploymentsPage(ctx, keyActor, "", "", page, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled deployment page error=%v", err)
	}
	if _, err := service.ListEnvironmentsPage(ctx, keyActor, "", page, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled environment page error=%v", err)
	}
	if _, err := service.ListDeploymentsPage(t.Context(), identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1"}, "", "", page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("missing deployment scope error=%v", err)
	}
}
