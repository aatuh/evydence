package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type deploymentPointReaderStub struct {
	point DeploymentPoint
	err   error
	calls int
}

func (r *deploymentPointReaderStub) GetDeploymentPoint(_ context.Context, _, _ string) (DeploymentPoint, error) {
	r.calls++
	return r.point, r.err
}

func TestDeploymentPointsAuthorizeTenantAndCurrentParent(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	point := DeploymentPoint{ProductID: "prod_1", Deployment: operationsdomain.DeploymentEvent{
		ID: "dep_1", TenantID: "ten_1", EnvironmentID: "env_1", ReleaseID: "rel_1",
		Status: "succeeded", StartedAt: now, CreatedAt: now,
	}}
	for _, test := range []struct {
		name  string
		actor identitydomain.Actor
		point DeploymentPoint
		want  error
	}{
		{name: "key scope", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"deployment:read"}}, point: point},
		{name: "matching product grant", actor: deploymentActor("product", "prod_1"), point: point},
		{name: "matching release grant", actor: deploymentActor("release", "rel_1"), point: point},
		{name: "matching tenant grant", actor: deploymentActor("tenant", "ten_1"), point: point},
		{name: "wrong tenant grant", actor: deploymentActor("tenant", "ten_other"), point: point, want: application.ErrForbidden},
		{name: "wrong product grant", actor: deploymentActor("product", "prod_other"), point: point, want: application.ErrForbidden},
		{name: "wrong release grant", actor: deploymentActor("release", "rel_other"), point: point, want: application.ErrForbidden},
		{name: "project grant does not cover deployment", actor: deploymentActor("project", "proj_1"), point: point, want: application.ErrForbidden},
		{name: "wrong tenant row", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"deployment:read"}}, point: DeploymentPoint{ProductID: "prod_1", Deployment: operationsdomain.DeploymentEvent{ID: "dep_1", TenantID: "ten_other", EnvironmentID: "env_1", ReleaseID: "rel_1"}}, want: ErrNotFound},
		{name: "missing parent", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"deployment:read"}}, point: DeploymentPoint{Deployment: point.Deployment}, want: ErrNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &deploymentPointReaderStub{point: test.point}
			service, err := NewDeploymentPoints(reader)
			if err != nil {
				t.Fatal(err)
			}
			deployment, err := service.GetDeployment(t.Context(), test.actor, "dep_1")
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("GetDeployment() error=%v, want %v", err, test.want)
			}
			if test.want == nil && deployment.ID != "dep_1" {
				t.Fatalf("deployment=%#v", deployment)
			}
			if reader.calls != 1 {
				t.Fatalf("reader calls=%d", reader.calls)
			}
		})
	}
}

func TestDeploymentPointsRejectMissingScopeBeforeStorage(t *testing.T) {
	reader := &deploymentPointReaderStub{}
	service, err := NewDeploymentPoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.GetDeployment(context.Background(), identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1"}, "dep_1")
	if !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
		t.Fatalf("missing-scope error=%v reader calls=%d", err, reader.calls)
	}
	_, err = service.GetDeployment(context.Background(), identitydomain.Actor{TenantID: "ten_1", Scopes: []string{"deployment:read"}}, "dep_1")
	if !errors.Is(err, application.ErrUnauthorized) || reader.calls != 0 {
		t.Fatalf("missing-identity error=%v reader calls=%d", err, reader.calls)
	}
	_, err = service.GetDeployment(context.Background(), identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"deployment:read"}}, " ")
	if !errors.Is(err, ErrNotFound) || reader.calls != 0 {
		t.Fatalf("blank-id error=%v reader calls=%d", err, reader.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = service.GetDeployment(ctx, identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"deployment:read"}}, "dep_1")
	if !errors.Is(err, context.Canceled) || reader.calls != 0 {
		t.Fatalf("canceled error=%v reader calls=%d", err, reader.calls)
	}
}

func deploymentActor(resourceType, resourceID string) identitydomain.Actor {
	return identitydomain.Actor{
		TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"deployment:read"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: resourceType, ResourceID: resourceID, Scopes: []string{"deployment:read"}}},
	}
}
