package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestReleaseBundleVerificationAuthorizationRequiresMatchingCurrentGrants(t *testing.T) {
	authorizer := NewReleaseBundleVerificationAuthorizer()
	request := application.AuthorizationRequest{Scope: "verify:read", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
	for _, tc := range []struct {
		name, resource, id, scope string
		allowed                   bool
	}{
		{"release", "release", "release", "verify:read", true},
		{"product", "product", "product", "verify:read", true},
		{"tenant", "tenant", "tenant", "verify:read", true},
		{"admin", "release", "release", "admin", true},
		{"wildcard", "product", "product", "*", true},
		{"wrong release", "release", "another", "verify:read", false},
		{"wrong tenant", "tenant", "another", "verify:read", false},
		{"wrong scope", "release", "release", "bundle:read", false},
		{"project is not release scope", "project", "project", "verify:read", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.resource, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			err := authorizer.Authorize(t.Context(), actor, request)
			if (err == nil) != tc.allowed {
				t.Fatal(err)
			}
			actor.ResourceGrants = nil
			if err := authorizer.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("removed grant retained access", err)
			}
		})
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"verify:read"}}
	if err := authorizer.Authorize(t.Context(), actor, request); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []application.AuthorizationRequest{{Scope: "bundle:read", Resources: request.Resources}, {Scope: "verify:read", TenantWide: true}, {Scope: "verify:read", ScopeOnly: true, Resources: request.Resources}, {Scope: "verify:read", Resources: application.ResourceReferences{ReleaseID: "release"}}, {Scope: "verify:read", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release", BuildID: "build"}}} {
		if err := authorizer.Authorize(t.Context(), actor, invalid); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("unsupported authorization input accepted", err)
		}
	}
}
