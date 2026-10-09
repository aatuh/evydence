package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPackageAccessAuthorizerRequiresMatchingCurrentResourceGrant(t *testing.T) {
	authorizer := NewPackageAccessAuthorizer()
	refs := application.ResourceReferences{ProductID: "prod_1", ReleaseID: "rel_1", CustomerPackageID: "csp_1"}
	for _, tc := range []struct {
		kind, id, scope string
		allowed         bool
	}{
		{"tenant", "ten_1", "package:read", true}, {"product", "prod_1", "package:read", true}, {"release", "rel_1", "package:read", true}, {"customer_security_package", "csp_1", "package:read", true},
		{"customer_security_package", "csp_other", "package:read", false}, {"release", "", "package:read", false}, {"product", "prod_other", "package:read", false}, {"tenant", "ten_other", "package:read", false}, {"product", "prod_1", "report:read", false}, {"project", "proj_1", "package:read", false},
	} {
		t.Run(tc.kind+tc.id+tc.scope, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "ten_1", UserID: "user_1", Scopes: []string{"package:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			err := authorizer.Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "package:read", Resources: refs})
			if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"package:read"}}
	if err := authorizer.Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "package:read", Resources: refs}); err != nil {
		t.Fatal(err)
	}
	if err := authorizer.Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "package:read", Resources: application.ResourceReferences{CustomerPackageID: "csp_1"}}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
}
