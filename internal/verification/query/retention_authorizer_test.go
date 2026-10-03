package query

import (
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestRetentionAuthorizerRequiresTenantWideGrantAndKnownOperation(t *testing.T) {
	auth := NewRetentionAuthorizer()
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"admin", "verify:read"}}
	for _, scope := range []string{"admin", "verify:read"} {
		req := application.AuthorizationRequest{Scope: scope, TenantWide: true}
		if err := auth.Authorize(t.Context(), actor, req); err == nil {
			t.Fatal("human without tenant grant accepted")
		}
		actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{scope}}}
		if err := auth.Authorize(t.Context(), actor, req); err == nil {
			t.Fatal("foreign grant accepted")
		}
		actor.ResourceGrants[0].ResourceID = "tenant"
		if err := auth.Authorize(t.Context(), actor, req); err != nil {
			t.Fatal(err)
		}
		actor.ResourceGrants = nil
	}
	actor.UserID, actor.KeyID = "", "key"
	if err := auth.Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: "admin", TenantWide: true}); err != nil {
		t.Fatal(err)
	}
	for _, req := range []application.AuthorizationRequest{{Scope: "keys:admin", TenantWide: true}, {Scope: "admin"}, {Scope: "admin", TenantWide: true, ScopeOnly: true}, {Scope: "verify:read", TenantWide: true, Resources: application.ResourceReferences{ReleaseID: "release"}}} {
		if err := auth.Authorize(t.Context(), actor, req); err == nil {
			t.Fatal("unsupported policy accepted", req)
		}
	}
}
