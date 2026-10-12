package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestBundleImportAuthorizerRequiresMatchingTenantWriteGrant(t *testing.T) {
	for _, tc := range []struct {
		kind, id, scope string
		allowed         bool
	}{
		{"tenant", "ten_1", "bundle:write", true}, {"tenant", "ten_other", "bundle:write", false}, {"product", "prod_1", "bundle:write", false}, {"release", "rel_1", "bundle:write", false}, {"tenant", "ten_1", "bundle:read", false},
	} {
		t.Run(tc.kind+tc.id+tc.scope, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "ten_1", UserID: "user_1", Scopes: []string{"bundle:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			for _, request := range []application.AuthorizationRequest{{Action: authz.ActionBundleImport, ScopeOnly: true}, {Action: authz.ActionBundleImport, TenantWide: true}} {
				err := NewBundleImportAuthorizer().Authorize(t.Context(), actor, request)
				if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
					t.Fatal(err)
				}
			}
		})
	}
}
