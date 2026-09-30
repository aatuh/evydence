package query

import (
	"context"
	"errors"
	"testing"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestCatalogAuthorizerPreservesActorScopeAndGrantBoundaries(t *testing.T) {
	product := application.ResourceReferences{ProductID: "prod_1"}
	project := application.ResourceReferences{ProductID: "prod_1", ProjectID: "proj_1"}
	release := application.ResourceReferences{ProductID: "prod_1", ReleaseID: "rel_1"}
	build := application.ResourceReferences{ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1", BuildID: "bld_1"}
	for _, test := range []struct {
		name    string
		actor   identitydomain.Actor
		request application.AuthorizationRequest
		want    error
	}{
		{name: "missing identity", actor: identitydomain.Actor{TenantID: "ten_1", Scopes: []string{"product:read"}}, request: application.AuthorizationRequest{Scope: "product:read", ScopeOnly: true}, want: application.ErrUnauthorized},
		{name: "missing tenant", actor: identitydomain.Actor{KeyID: "key_1", Scopes: []string{"product:read"}}, request: application.AuthorizationRequest{Scope: "product:read", ScopeOnly: true}, want: application.ErrUnauthorized},
		{name: "missing scope", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1"}, request: application.AuthorizationRequest{Scope: "product:read", ScopeOnly: true}, want: application.ErrForbidden},
		{name: "key scope", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"product:read"}}, request: application.AuthorizationRequest{Scope: "product:read", Resources: product}},
		{name: "collector scope", actor: identitydomain.Actor{TenantID: "ten_1", CollectorID: "col_1", Scopes: []string{"project:read"}}, request: application.AuthorizationRequest{Scope: "project:read", Resources: project}},
		{name: "admin scope", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"admin"}}, request: application.AuthorizationRequest{Scope: "release:read", Resources: release}},
		{name: "wildcard scope", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"*"}}, request: application.AuthorizationRequest{Scope: "product:read", Resources: product}},
		{name: "product write key", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"product:write"}}, request: application.AuthorizationRequest{Scope: "product:write", TenantWide: true}},
		{name: "product write tenant grant", actor: catalogActor("product:write", "tenant", "ten_1", "product:write"), request: application.AuthorizationRequest{Scope: "product:write", TenantWide: true}},
		{name: "product write product grant denied", actor: catalogActor("product:write", "product", "prod_1", "product:write"), request: application.AuthorizationRequest{Scope: "product:write", TenantWide: true}, want: application.ErrForbidden},
		{name: "product write wrong tenant grant denied", actor: catalogActor("product:write", "tenant", "ten_2", "product:write"), request: application.AuthorizationRequest{Scope: "product:write", TenantWide: true}, want: application.ErrForbidden},
		{name: "product write scope only denied", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"product:write"}}, request: application.AuthorizationRequest{Scope: "product:write", ScopeOnly: true}, want: application.ErrForbidden},
		{name: "product write resource scope denied", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"product:write"}}, request: application.AuthorizationRequest{Scope: "product:write", Resources: product}, want: application.ErrForbidden},
		{name: "project write key scope only", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"project:write"}}, request: application.AuthorizationRequest{Scope: "project:write", ScopeOnly: true}},
		{name: "project write key product", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"project:write"}}, request: application.AuthorizationRequest{Scope: "project:write", Resources: product}},
		{name: "project write product grant", actor: catalogActor("project:write", "product", "prod_1", "project:write"), request: application.AuthorizationRequest{Scope: "project:write", Resources: product}},
		{name: "project write wrong product grant", actor: catalogActor("project:write", "product", "prod_2", "project:write"), request: application.AuthorizationRequest{Scope: "project:write", Resources: product}, want: application.ErrForbidden},
		{name: "project write tenant grant", actor: catalogActor("project:write", "tenant", "ten_1", "project:write"), request: application.AuthorizationRequest{Scope: "project:write", Resources: product}},
		{name: "project write project grant cannot create", actor: catalogActor("project:write", "project", "proj_1", "project:write"), request: application.AuthorizationRequest{Scope: "project:write", Resources: product}, want: application.ErrForbidden},
		{name: "release write key scope only", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"release:write"}}, request: application.AuthorizationRequest{Scope: "release:write", ScopeOnly: true}},
		{name: "release write product grant", actor: catalogActor("release:write", "product", "prod_1", "release:write"), request: application.AuthorizationRequest{Scope: "release:write", Resources: product}},
		{name: "release write wrong product grant", actor: catalogActor("release:write", "product", "prod_2", "release:write"), request: application.AuthorizationRequest{Scope: "release:write", Resources: product}, want: application.ErrForbidden},
		{name: "release write release grant cannot create", actor: catalogActor("release:write", "release", "rel_1", "release:write"), request: application.AuthorizationRequest{Scope: "release:write", Resources: product}, want: application.ErrForbidden},
		{name: "human scope only", actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"product:read"}}, request: application.AuthorizationRequest{Scope: "product:read", ScopeOnly: true}},
		{name: "human no grants", actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"product:read"}}, request: application.AuthorizationRequest{Scope: "product:read", Resources: product}, want: application.ErrForbidden},
		{name: "tenant grant", actor: catalogActor("product:read", "tenant", "ten_1", "product:read"), request: application.AuthorizationRequest{Scope: "product:read", Resources: product}},
		{name: "tenant-wide grant", actor: catalogActor("product:read", "tenant", "ten_1", "product:read"), request: application.AuthorizationRequest{Scope: "product:read", ScopeOnly: true, TenantWide: true}},
		{name: "wrong tenant grant", actor: catalogActor("product:read", "tenant", "ten_2", "product:read"), request: application.AuthorizationRequest{Scope: "product:read", TenantWide: true}, want: application.ErrForbidden},
		{name: "product grant not tenant wide", actor: catalogActor("product:read", "product", "prod_1", "product:read"), request: application.AuthorizationRequest{Scope: "product:read", TenantWide: true}, want: application.ErrForbidden},
		{name: "product grant", actor: catalogActor("product:read", "product", "prod_1", "product:read"), request: application.AuthorizationRequest{Scope: "product:read", Resources: product}},
		{name: "product grant wrong product", actor: catalogActor("product:read", "product", "prod_2", "product:read"), request: application.AuthorizationRequest{Scope: "product:read", Resources: product}, want: application.ErrForbidden},
		{name: "product grant covers project", actor: catalogActor("project:read", "product", "prod_1", "project:read"), request: application.AuthorizationRequest{Scope: "project:read", Resources: project}},
		{name: "product grant covers release", actor: catalogActor("release:read", "product", "prod_1", "release:read"), request: application.AuthorizationRequest{Scope: "release:read", Resources: release}},
		{name: "project grant", actor: catalogActor("project:read", "project", "proj_1", "project:read"), request: application.AuthorizationRequest{Scope: "project:read", Resources: project}},
		{name: "project grant wrong project", actor: catalogActor("project:read", "project", "proj_2", "project:read"), request: application.AuthorizationRequest{Scope: "project:read", Resources: project}, want: application.ErrForbidden},
		{name: "project grant not product", actor: catalogActor("product:read", "project", "proj_1", "product:read"), request: application.AuthorizationRequest{Scope: "product:read", Resources: product}, want: application.ErrForbidden},
		{name: "release grant", actor: catalogActor("release:read", "release", "rel_1", "release:read"), request: application.AuthorizationRequest{Scope: "release:read", Resources: release}},
		{name: "release grant not project", actor: catalogActor("project:read", "release", "rel_1", "project:read"), request: application.AuthorizationRequest{Scope: "project:read", Resources: project}, want: application.ErrForbidden},
		{name: "build key scope", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"build:read"}}, request: application.AuthorizationRequest{Scope: "build:read", Resources: build}},
		{name: "build product grant", actor: catalogActor("build:read", "product", "prod_1", "build:read"), request: application.AuthorizationRequest{Scope: "build:read", Resources: build}},
		{name: "build project grant", actor: catalogActor("build:read", "project", "proj_1", "build:read"), request: application.AuthorizationRequest{Scope: "build:read", Resources: build}},
		{name: "build release grant", actor: catalogActor("build:read", "release", "rel_1", "build:read"), request: application.AuthorizationRequest{Scope: "build:read", Resources: build}},
		{name: "build wrong project grant", actor: catalogActor("build:read", "project", "proj_other", "build:read"), request: application.AuthorizationRequest{Scope: "build:read", Resources: build}, want: application.ErrForbidden},
		{name: "build wrong release grant", actor: catalogActor("build:read", "release", "rel_other", "build:read"), request: application.AuthorizationRequest{Scope: "build:read", Resources: build}, want: application.ErrForbidden},
		{name: "grant wrong scope", actor: catalogActor("product:read", "product", "prod_1", "project:read"), request: application.AuthorizationRequest{Scope: "product:read", Resources: product}, want: application.ErrForbidden},
		{name: "admin grant scope", actor: catalogActor("product:read", "product", "prod_1", "admin"), request: application.AuthorizationRequest{Scope: "product:read", Resources: product}},
		{name: "wildcard grant scope", actor: catalogActor("product:read", "product", "prod_1", "*"), request: application.AuthorizationRequest{Scope: "product:read", Resources: product}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := NewCatalogAuthorizer().Authorize(t.Context(), test.actor, test.request)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Authorize() error=%v, want %v", err, test.want)
			}
		})
	}
}

func TestCatalogAuthorizerFailsClosedOnInvalidProjectionAndCancellation(t *testing.T) {
	authorizer := NewCatalogAuthorizer()
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"product:read", "project:read", "release:read", "build:read"}}
	for _, request := range []application.AuthorizationRequest{
		{Scope: "project:read", Resources: application.ResourceReferences{ProductID: "prod_1"}},
		{Scope: "project:read", Resources: application.ResourceReferences{ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1"}},
		{Scope: "release:read", Resources: application.ResourceReferences{ReleaseID: "rel_1"}},
		{Scope: "product:read", Resources: application.ResourceReferences{ProductID: "prod_1", ProjectID: "proj_1"}},
		{Scope: "build:read", Resources: application.ResourceReferences{ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1"}},
		{Scope: "build:read", Resources: application.ResourceReferences{ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1", BuildID: "bld_1", ArtifactID: "art_1"}},
		{Scope: "evidence:read", ScopeOnly: true},
	} {
		if err := authorizer.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatalf("invalid request %#v allowed: %v", request, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: "project:read", ScopeOnly: true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authorization error=%v", err)
	}
}

func catalogActor(actorScope, resourceType, resourceID, grantScope string) identitydomain.Actor {
	return identitydomain.Actor{
		TenantID: "ten_1", UserID: "usr_1", Scopes: []string{actorScope},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: resourceType, ResourceID: resourceID, Scopes: []string{grantScope}}},
	}
}
