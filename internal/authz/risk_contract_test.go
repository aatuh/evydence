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
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestRiskFactoriesRequireOwnTypedActionEvenForSharedScopes(t *testing.T) {
	policies := []struct {
		action authz.Action
		scope  string
		policy application.Authorizer
	}{
		{"vulnerability_decisions.record", "evidence:write", riskapp.NewVulnerabilityDecisionWriteAuthorizer()},
		{"approvals.record", "release:write", riskapp.NewApprovalWriteAuthorizer()},
		{"waivers.manage", "policy:write", riskapp.NewWaiverWriteAuthorizer()},
		{"exceptions.manage", "release:write", riskapp.NewExceptionWriteAuthorizer()},
		{"vulnerability_workflows.record", "security:write", riskapp.NewVulnerabilityWorkflowWriteAuthorizer()},
		{"policy_evaluations.create", "verify:read", riskapp.NewPolicyEvaluationAuthorizer()},
		{"custom_policies.create", "policy:write", riskapp.NewCustomPolicyAuthorizer()},
		{"custom_policies.evaluate", "policy:read", riskapp.NewCustomPolicyAuthorizer()},
	}
	for _, tc := range policies {
		t.Run(string(tc.action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
			refs := application.ResourceReferences{ProductID: "product", ReleaseID: "release"}
			if err := tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: tc.action, Resources: refs}); err != nil {
				t.Fatalf("typed action denied: %v", err)
			}
			if err := tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: tc.action, ScopeOnly: true}); err != nil {
				t.Fatal("typed preflight", err)
			}
			human := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{tc.scope}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{tc.scope}}}}
			if err := tc.policy.Authorize(t.Context(), human, application.AuthorizationRequest{Action: tc.action, Resources: refs}); err != nil {
				t.Fatal("current SSO grant", err)
			}
			human.ResourceGrants = nil
			if err := tc.policy.Authorize(t.Context(), human, application.AuthorizationRequest{Action: tc.action, Resources: refs}); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("revoked SSO grant", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := tc.policy.Authorize(ctx, actor, application.AuthorizationRequest{Action: tc.action, Resources: refs}); !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation", err)
			}
			actor.Scopes = []string{"*"}
			for _, bad := range []application.AuthorizationRequest{
				{Scope: tc.scope, Resources: refs}, {Action: tc.action, Scope: tc.scope, Resources: refs},
				{Action: tc.action, ScopeOnly: true, TenantWide: true},
				{Action: tc.action, ScopeOnly: true, Resources: refs},
				{Action: tc.action, TenantWide: true, Resources: refs},
				{Action: tc.action, Resources: application.ResourceReferences{TenantID: "foreign", ProductID: "product"}},
				{Action: "unknown", Resources: refs},
			} {
				if err := tc.policy.Authorize(t.Context(), actor, bad); !errors.Is(err, application.ErrForbidden) {
					t.Fatalf("unsupported request allowed: %#v: %v", bad, err)
				}
			}
			for _, other := range policies {
				if other.action == tc.action || (tc.action == "custom_policies.create" || tc.action == "custom_policies.evaluate") && (other.action == "custom_policies.create" || other.action == "custom_policies.evaluate") {
					continue
				}
				if err := tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: other.action, Resources: refs}); !errors.Is(err, application.ErrForbidden) {
					t.Fatalf("foreign action %s allowed: %v", other.action, err)
				}
			}
		})
	}
}

func TestRiskWorkflowRequestsConstructActionsNotScopeStrings(t *testing.T) {
	for _, path := range []string{
		"../risk/app/vulnerability_decision_commands.go", "../risk/app/approval_commands.go",
		"../risk/app/waiver_commands.go", "../risk/app/exception_commands.go",
		"../risk/app/vulnerability_workflow_commands.go", "../risk/app/policy_evaluation_commands.go",
		"../risk/app/custom_policy_commands.go",
		"../adapters/httpapi/risk_command_fixture_ports_test.go",
	} {
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
					t.Errorf("%s unkeyed request", path)
					continue
				}
				key, ok := pair.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if key.Name == "Scope" {
					t.Errorf("%s scope-string authority", path)
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
			t.Fatalf("%s request coverage disappeared", path)
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "../risk/app/vulnerability_decision_authorizer.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	centralCalls := 0
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope" {
			t.Errorf("local risk grant policy: %s", selector.Sel.Name)
		}
		if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "authz" && selector.Sel.Name == "Authorize" {
			centralCalls++
		}
		return true
	})
	if centralCalls == 0 {
		t.Fatal("risk factories no longer delegate to central policy")
	}
}
