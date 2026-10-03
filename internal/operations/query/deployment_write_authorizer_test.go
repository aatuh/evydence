package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestDeploymentWriteAuthorizerRequiresScopedProductOrTenantGrant(t *testing.T) {
	auth := NewDeploymentWriteAuthorizer()
	request := application.AuthorizationRequest{Scope: "deployment:write", Resources: application.ResourceReferences{ProductID: "product"}}
	for _, tc := range []struct {
		actor identitydomain.Actor
		allow bool
	}{
		{identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:write"}}, true},
		{identitydomain.Actor{TenantID: "tenant", CollectorID: "collector", Scopes: []string{"deployment:write"}}, true},
		{identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:read"}}, false},
		{identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"deployment:write"}}, false},
		{identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"deployment:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"deployment:write"}}}}, true},
		{identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}}, true},
		{identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"deployment:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "other", Scopes: []string{"deployment:write"}}}}, false},
		{identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"deployment:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"deployment:write"}}}}, false},
	} {
		err := auth.Authorize(t.Context(), tc.actor, request)
		if tc.allow && err != nil || !tc.allow && !errors.Is(err, application.ErrForbidden) {
			t.Fatal(tc, err)
		}
	}
}

func TestDeploymentWriteAuthorizerAcceptsVerifiedDeploymentCoordinates(t *testing.T) {
	auth := NewDeploymentWriteAuthorizer()
	r := application.AuthorizationRequest{Scope: "deployment:write", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release", EnvironmentID: "env"}}
	for _, tc := range []struct {
		kind, id string
		allow    bool
	}{{"tenant", "tenant", true}, {"product", "product", true}, {"release", "release", true}, {"release", "other", false}, {"product", "other", false}, {"project", "project", false}, {"environment", "env", false}} {
		a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"deployment:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{"deployment:write"}}}}
		err := auth.Authorize(t.Context(), a, r)
		if tc.allow && err != nil || !tc.allow && !errors.Is(err, application.ErrForbidden) {
			t.Fatal(tc, err)
		}
		a.ResourceGrants = nil
		if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("removed grant remained authorized", err)
		}
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:write"}}
	for _, refs := range []application.ResourceReferences{{ProductID: "product", ReleaseID: "release"}, {ProductID: "product", EnvironmentID: "env"}, {ProductID: "product", ReleaseID: "release", EnvironmentID: "env", ArtifactID: "artifact"}} {
		r.Resources = refs
		if err := auth.Authorize(t.Context(), a, r); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("unexpected coordinate capability", refs, err)
		}
	}
}
