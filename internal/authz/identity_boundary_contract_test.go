package authz_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestSessionRevocationDelegateBindsTypedSelfAndAdministrativeActions(t *testing.T) {
	policy := identityapp.NewSSOSessionRevocationAuthorizer()
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session"}
	if err := policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: "sso_sessions.logout"}); err != nil {
		t.Fatal("typed owner logout denied", err)
	}
	for _, r := range []application.AuthorizationRequest{{Scope: "identity:logout"}, {Action: "sso_sessions.logout", Scope: "identity:logout"}, {Action: "sso_sessions.logout", ScopeOnly: true}, {Action: "sso_sessions.logout", TenantWide: true}, {Action: "sso_sessions.logout", Resources: application.ResourceReferences{ProductID: "foreign"}}, {Action: authz.ActionMembershipsManage, TenantWide: true}} {
		if err := policy.Authorize(t.Context(), actor, r); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("self logout promoted to other authority", r, err)
		}
	}
	actor.Scopes = []string{"identity:admin"}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"identity:admin"}}}
	if err := policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: authz.ActionMembershipsManage, TenantWide: true}); err != nil {
		t.Fatal("current tenant session administrator denied", err)
	}
}

func TestIdentityAndMetricsNoLongerSelectPolicyThroughLocalActorPredicates(t *testing.T) {
	for _, path := range []string{"../identity/app/api_key_commands.go", "../identity/app/sso_session_revocation_commands.go", "../operations/query/metrics.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope" || selector.Sel.Name == "ResourceGrants") {
				t.Errorf("%s retains a local actor policy", path)
			}
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typ, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || typ.Sel.Name != "AuthorizationRequest" {
				return true
			}
			for _, element := range literal.Elts {
				if field, ok := element.(*ast.KeyValueExpr); ok {
					if name, ok := field.Key.(*ast.Ident); ok && name.Name == "Scope" {
						t.Errorf("%s retains a scope-string action", path)
					}
				}
			}
			return true
		})
	}
}
