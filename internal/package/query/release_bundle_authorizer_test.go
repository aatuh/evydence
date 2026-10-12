package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestReleaseBundleAuthorizerRequiresMatchingWriteGrants(t *testing.T) {
	refs := application.ResourceReferences{ProductID: "product", ReleaseID: "release"}
	for _, tc := range []struct {
		kind, id, scope string
		allowed         bool
	}{
		{"tenant", "tenant", "bundle:write", true}, {"tenant", "other", "bundle:write", false}, {"product", "product", "bundle:write", true}, {"product", "other", "bundle:write", false}, {"release", "release", "bundle:write", true}, {"release", "other", "bundle:write", false}, {"tenant", "tenant", "bundle:read", false}, {"product", "product", "*", true}, {"product", "product", "", false},
	} {
		t.Run(tc.kind+tc.id+tc.scope, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"bundle:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			err := NewReleaseBundleAuthorizer().Authorize(t.Context(), actor, application.AuthorizationRequest{Action: authz.ActionReleaseBundlesCreate, Resources: refs})
			if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatal(err)
			}
		})
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"bundle:write"}}
	for _, request := range []application.AuthorizationRequest{{Action: authz.ActionReleaseBundlesCreate, ScopeOnly: true, Resources: refs}, {Scope: "bundle:read", Resources: refs}, {Action: authz.ActionReleaseBundlesCreate, Resources: application.ResourceReferences{ReleaseID: "release"}}, {Action: authz.ActionReleaseBundlesCreate, TenantWide: true, Resources: refs}} {
		if err := NewReleaseBundleAuthorizer().Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatal(err)
		}
	}
}
