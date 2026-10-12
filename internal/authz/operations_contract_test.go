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
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func TestOperationsFactoriesRequireTypedActionsAndRejectScopeFallback(t *testing.T) {
	for _, tc := range []struct {
		action authz.Action
		scope  string
		refs   application.ResourceReferences
		policy application.Authorizer
		tenant bool
	}{
		{"environments.create", "deployment:write", application.ResourceReferences{ProductID: "product"}, operationsquery.NewDeploymentWriteAuthorizer(), false},
		{"deployments.record", "deployment:write", application.ResourceReferences{ProductID: "product", ReleaseID: "release", EnvironmentID: "environment"}, operationsquery.NewDeploymentWriteAuthorizer(), false},
		{"incidents.manage", "incident:write", application.ResourceReferences{ProductID: "product"}, operationsapp.NewIncidentWriteAuthorizer(), true},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
			request := application.AuthorizationRequest{Action: tc.action, Resources: tc.refs}
			if err := tc.policy.Authorize(t.Context(), actor, request); err != nil {
				t.Fatalf("typed action denied: %v", err)
			}
			if err := tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: tc.action, ScopeOnly: true}); err != nil {
				t.Fatalf("typed preflight denied: %v", err)
			}
			err := tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: tc.action, TenantWide: true})
			if tc.tenant && err != nil || !tc.tenant && !errors.Is(err, application.ErrForbidden) {
				t.Fatalf("tenant phase allowed=%v: %v", tc.tenant, err)
			}
			for _, bad := range []application.AuthorizationRequest{
				{Scope: tc.scope, Resources: tc.refs},
				{Action: tc.action, Scope: tc.scope, Resources: tc.refs},
				{Action: tc.action, ScopeOnly: true, TenantWide: true},
				{Action: tc.action, ScopeOnly: true, Resources: tc.refs},
				{Action: tc.action, TenantWide: true, Resources: tc.refs},
				{Action: tc.action, Resources: application.ResourceReferences{TenantID: "foreign", ProductID: "product"}},
				{Action: authz.ActionOutboxReplay, Resources: tc.refs},
				{Action: "unknown", Resources: tc.refs},
			} {
				if err := tc.policy.Authorize(t.Context(), actor, bad); !errors.Is(err, application.ErrForbidden) {
					t.Fatalf("unsupported request allowed: %#v: %v", bad, err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := tc.policy.Authorize(ctx, actor, request); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation changed: %v", err)
			}
		})
	}
}

func TestOperationsCommandRequestsHaveActionsNotScopeStrings(t *testing.T) {
	for _, path := range []string{
		"../operations/app/deployment_commands.go", "../operations/app/deployment_environment_commands.go",
		"../operations/app/deployment_creation_guard.go", "../operations/app/incident_commands.go",
		"../operations/app/incident_webhook_commands.go",
		"../evidence/app/deployment_evidence.go",
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
					t.Errorf("%s unkeyed authorization request", path)
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
				t.Errorf("%s omits typed authority", path)
			}
			return true
		})
		if requests == 0 {
			t.Fatalf("%s authorization request coverage disappeared", path)
		}
	}
}

func TestOperationsDelegatesGrantDecisionsToCentralPolicy(t *testing.T) {
	for _, path := range []string{
		"../operations/app/incident_authorizer.go", "../operations/query/deployment_write_authorizer.go",
		"../operations/query/deployment_points.go", "../operations/query/deployment_lists.go",
	} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch selector.Sel.Name {
			case "ResourceGrants", "HasScope", "HasExplicitScope":
				t.Errorf("%s reintroduced local grant policy: %s", path, selector.Sel.Name)
			case "Authorize", "ReadVisibility":
				if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "authz" {
					calls++
				}
			}
			return true
		})
		if calls == 0 {
			t.Fatalf("%s no longer calls central policy", path)
		}
	}
}
