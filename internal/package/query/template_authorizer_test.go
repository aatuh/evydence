package query

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestTemplateAuthorizerRequiresTenantWideReportGrant(t *testing.T) {
	for _, tc := range []struct {
		kind, id, scope string
		allowed         bool
	}{
		{"tenant", "ten_1", "report:read", true}, {"tenant", "ten_other", "report:read", false}, {"product", "prod_1", "report:read", false}, {"release", "rel_1", "report:read", false}, {"tenant", "ten_1", "package:read", false},
	} {
		t.Run(tc.kind+tc.id+tc.scope, func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "ten_1", UserID: "user_1", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: tc.kind, ResourceID: tc.id, Scopes: []string{tc.scope}}}}
			for _, request := range []application.AuthorizationRequest{{Scope: "report:read", ScopeOnly: true}, {Scope: "report:read", TenantWide: true}} {
				err := NewTemplateAuthorizer().Authorize(t.Context(), actor, request)
				if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
					t.Fatal(err)
				}
			}
		})
	}
}
