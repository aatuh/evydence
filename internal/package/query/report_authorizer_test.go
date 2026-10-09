package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestReportAuthorizerRestrictsExactProductReleaseReferences(t *testing.T) {
	authorizer := NewReportAuthorizer()
	for _, tc := range []struct {
		kind, id, scope string
		allowed         bool
	}{
		{"tenant", "ten_1", "report:read", true}, {"product", "prod_1", "report:read", true}, {"release", "rel_1", "report:read", true},
		{"product", "prod_other", "report:read", false}, {"release", "", "report:read", false}, {"tenant", "ten_other", "report:read", false}, {"product", "prod_1", "package:read", false},
	} {
		t.Run(tc.kind+tc.id+tc.scope, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "ten_1", UserID: "user_1", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			err := authorizer.Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "report:read", Resources: application.ResourceReferences{ProductID: "prod_1", ReleaseID: "rel_1"}})
			if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"report:read"}}
	for _, refs := range []application.ResourceReferences{{}, {ReleaseID: "rel_1"}, {ProductID: "prod_1", CustomerPackageID: "csp_1"}} {
		if err := authorizer.Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "report:read", Resources: refs}); !errors.Is(err, application.ErrForbidden) {
			t.Fatal(err)
		}
	}
}
