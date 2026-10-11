package authz_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestAdministrativeFactoriesRequireOwnTypedActionAndCurrentTenantAuthority(t *testing.T) {
	for _, tc := range []struct {
		action authz.Action
		scope  string
		policy application.Authorizer
	}{
		{authz.ActionAPIKeysManage, "admin", identityapp.NewAPIKeyWriteAuthorizer()},
		{authz.ActionMembershipsManage, "identity:admin", identityapp.NewMembershipWriteAuthorizer()},
		{authz.ActionCollectorsManage, "collector:admin", integrationapp.NewCollectorWriteAuthorizer()},
		{authz.ActionControlsManage, "controls:admin", riskapp.NewControlAdminAuthorizer()},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			request := application.AuthorizationRequest{Action: tc.action, TenantWide: true}
			for _, actor := range []identitydomain.Actor{
				{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}},
				{TenantID: "tenant", CollectorID: "collector", KeyID: "collector-key", Scopes: []string{tc.scope}},
			} {
				if err := tc.policy.Authorize(t.Context(), actor, request); err != nil {
					t.Fatalf("typed issued capability denied: %v", err)
				}
			}
			human := identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session", Scopes: []string{tc.scope}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}}
			if err := tc.policy.Authorize(t.Context(), human, request); err != nil {
				t.Fatalf("current human tenant grant denied: %v", err)
			}
			for _, grant := range []identitydomain.ResourceGrant{
				{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{tc.scope}},
				{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}},
			} {
				human.ResourceGrants = []identitydomain.ResourceGrant{grant}
				if err := tc.policy.Authorize(t.Context(), human, request); !errors.Is(err, application.ErrForbidden) {
					t.Fatalf("inapplicable grant authorized administration: %v", err)
				}
			}
			human.ResourceGrants = nil
			if err := tc.policy.Authorize(t.Context(), human, request); !errors.Is(err, application.ErrForbidden) {
				t.Fatalf("revoked human grant authorized administration: %v", err)
			}
			actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}
			for _, bad := range []application.AuthorizationRequest{
				{Scope: tc.scope, TenantWide: true},
				{Action: tc.action, Scope: tc.scope, TenantWide: true},
				{Action: tc.action},
				{Action: tc.action, TenantWide: true, ScopeOnly: true},
				{Action: tc.action, TenantWide: true, Resources: application.ResourceReferences{TenantID: "foreign"}},
				{Action: tc.action, TenantWide: true, Resources: application.ResourceReferences{OrganizationID: "foreign"}},
				{Action: "unknown", TenantWide: true},
			} {
				if err := tc.policy.Authorize(t.Context(), actor, bad); !errors.Is(err, application.ErrForbidden) {
					t.Fatalf("unsupported administrative request authorized: %#v error=%v", bad, err)
				}
			}
			for _, other := range []authz.Action{authz.ActionAPIKeysManage, authz.ActionMembershipsManage, authz.ActionCollectorsManage, authz.ActionControlsManage, authz.ActionProductsCreate, authz.ActionOutboxReplay} {
				if other == tc.action {
					continue
				}
				if err := tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: other, TenantWide: true}); !errors.Is(err, application.ErrForbidden) {
					t.Fatalf("factory selected foreign operation %s: %v", other, err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := tc.policy.Authorize(ctx, actor, request); !errors.Is(err, context.Canceled) {
				t.Fatalf("administrative cancellation changed: %v", err)
			}
		})
	}
}

func TestAdministrativeRequestHelpersConstructActionsNotScopes(t *testing.T) {
	for _, path := range []string{"../identity/app/api_key_commands.go", "../identity/app/membership_commands.go", "../integration/app/collector_commands.go", "../risk/app/control_commands.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		requests := 0
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			kind, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || kind.Sel.Name != "AuthorizationRequest" {
				return true
			}
			requests++
			action := false
			for _, field := range literal.Elts {
				pair, ok := field.(*ast.KeyValueExpr)
				if !ok {
					t.Errorf("%s constructs unkeyed authority", path)
					continue
				}
				key, ok := pair.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if key.Name == "Scope" {
					t.Errorf("%s retains scope-string authority", path)
				}
				if key.Name == "Action" {
					action = true
				}
			}
			if !action {
				t.Errorf("%s omitted typed authority", path)
			}
			return true
		})
		if requests == 0 {
			t.Fatalf("%s request-helper coverage disappeared", path)
		}
	}
}
