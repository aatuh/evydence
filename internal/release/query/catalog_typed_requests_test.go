package query

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestCatalogPolicyRequiresTypedActionAndRejectsScopeFallback(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}
	policy := NewCatalogAuthorizer()
	valid := application.AuthorizationRequest{Action: authz.ActionProductsRead, Resources: application.ResourceReferences{ProductID: "product"}}
	if err := policy.Authorize(t.Context(), actor, valid); err != nil {
		t.Fatalf("typed product action denied: %v", err)
	}
	for _, request := range []application.AuthorizationRequest{
		{Scope: "product:read", Resources: valid.Resources},
		{Action: valid.Action, Scope: "product:read", Resources: valid.Resources},
		{Action: "unknown", Scope: "product:read", Resources: valid.Resources},
		{Action: authz.ActionAPIKeysRead, TenantWide: true},
		{Action: authz.ActionOutboxReplay},
	} {
		if err := policy.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatalf("ambiguous, legacy, or foreign-family request authorized: %#v error=%v", request, err)
		}
	}
}

func TestBuildAndCandidateFactoriesRequireTheirOwnTypedAction(t *testing.T) {
	reader := &buildArtifactPointReaderFake{}
	build, err := NewBuildAuthorizer(reader)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := NewBuildAttestationAuthorizer(reader)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewCandidateAuthorizer(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}
	for _, tc := range []struct {
		policy    application.Authorizer
		action    authz.Action
		resources application.ResourceReferences
	}{
		{build, authz.ActionBuildsCreate, application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}},
		{attestation, authz.ActionBuildAttestationsCreate, application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build"}},
		{candidate, authz.ActionReleaseCandidatesCreate, application.ResourceReferences{ProductID: "product", ReleaseID: "release"}},
	} {
		request := application.AuthorizationRequest{Action: tc.action, Resources: tc.resources}
		if err := tc.policy.Authorize(t.Context(), actor, request); err != nil {
			t.Fatalf("registered operation %s denied: %v", tc.action, err)
		}
		for _, wrong := range []authz.Action{authz.ActionProductsRead, authz.ActionAPIKeysRead, authz.ActionBuildsCreate, authz.ActionBuildAttestationsCreate, authz.ActionReleaseCandidatesCreate, "unknown"} {
			if wrong == tc.action {
				continue
			}
			request.Action = wrong
			if err := tc.policy.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
				t.Fatalf("factory accepted %s instead of %s: %v", wrong, tc.action, err)
			}
		}
		request.Action, request.Scope = tc.action, "build:write"
		if err := tc.policy.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatalf("factory accepted action/scope ambiguity: %v", err)
		}
	}
}

func TestCatalogCallersDoNotConstructScopeStringAuthorizationRequests(t *testing.T) {
	for _, path := range []string{
		"products.go", "catalog_points.go", "build_points.go", "release_candidates.go", "evidence_flow.go",
		"../app/product_commands.go", "../app/project_commands.go", "../app/release_commands.go", "../app/catalog_creation_guard.go",
		"../app/build_commands.go", "../app/build_creation_guard.go", "../app/attestations.go", "../app/build_attestation_creation_guard.go",
		"../app/release_state_commands.go", "../app/candidate_state_commands.go", "../app/state_transition_guard.go",
		"../app/candidate_commands.go", "../app/candidate_creation_guard.go",
	} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			kind, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || kind.Sel.Name != "AuthorizationRequest" {
				return true
			}
			hasAction := false
			for _, field := range literal.Elts {
				pair, ok := field.(*ast.KeyValueExpr)
				if !ok {
					t.Errorf("%s uses an unkeyed authorization request", path)
					continue
				}
				key, ok := pair.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if key.Name == "Scope" {
					t.Errorf("%s still selects authority using a scope string", path)
				}
				if key.Name == "Action" {
					hasAction = true
				}
			}
			if !hasAction {
				t.Errorf("%s has an authorization request without a typed action", path)
			}
			return true
		})
	}
	file, err := parser.ParseFile(token.NewFileSet(), "catalog_authorizer.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "catalogAction" {
			t.Fatal("catalog scope-to-action fallback remains in production")
		}
	}
	for _, path := range []string{"../app/service.go", "../app/workflows.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) < 3 {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || method.Sel.Name != "authorize" {
				return true
			}
			if scope, ok := call.Args[2].(*ast.Ident); ok {
				switch scope.Name {
				case "ScopeProductRead", "ScopeProductWrite", "ScopeProjectRead", "ScopeProjectWrite", "ScopeReleaseRead", "ScopeReleaseWrite", "ScopeBuildRead", "ScopeBuildWrite":
					t.Errorf("%s keeps a catalog scope-string caller: %s", path, scope.Name)
				}
			}
			return true
		})
	}
}
