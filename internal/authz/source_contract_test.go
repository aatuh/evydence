package authz_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func TestSourceWriteDelegateRequiresRegisteredTypedOperationEnvelope(t *testing.T) {
	policy := integrationquery.NewSourceWriteAuthorizer()
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"source:write"}}
	refs := application.ResourceReferences{ProductID: "product", ProjectID: "project"}
	for _, action := range []authz.Action{"source_repositories.create", "source_commits.record", "source_branches.upsert", "pull_requests.record", "source_snapshots.record"} {
		for _, request := range []application.AuthorizationRequest{
			{Action: action, ScopeOnly: true}, {Action: action, TenantWide: true}, {Action: action, Resources: refs},
		} {
			if err := policy.Authorize(t.Context(), actor, request); err != nil {
				t.Fatal("typed source operation denied", request, err)
			}
		}
		for _, request := range []application.AuthorizationRequest{
			{Scope: "source:write", Resources: refs},
			{Action: action, Scope: "source:write", Resources: refs},
			{Action: action, ScopeOnly: true, TenantWide: true},
			{Action: action, ScopeOnly: true, Resources: refs},
			{Action: action, TenantWide: true, Resources: refs},
			{Action: action}, {Action: action, Resources: application.ResourceReferences{ProjectID: "project"}},
			{Action: "source_repositories.read", Resources: refs},
			{Action: authz.ActionBuildsCreate, Resources: refs},
		} {
			if err := policy.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("legacy/ambiguous/foreign operation envelope authorized", request, err)
			}
		}
	}
}

func TestSourceCommandAndReplayCallersSelectTheirOwnTypedAction(t *testing.T) {
	for _, tc := range []struct{ path, function, action string }{
		{"source_commit_commands.go", "RecordSourceCommit", "ActionSourceCommitsRecord"},
		{"source_branch_commands.go", "UpsertSourceBranch", "ActionSourceBranchesUpsert"},
		{"pull_request_commands.go", "RecordPullRequest", "ActionPullRequestsRecord"},
		{"source_snapshot_commands.go", "RecordSourceSnapshot", "ActionSourceSnapshotsRecord"},
		{"source_snapshot_guard.go", "AuthorizeSourceSnapshot", "ActionSourceSnapshotsRecord"},
		{"source_write_guard.go", "AuthorizeSourceCommitRecording", "ActionSourceCommitsRecord"},
		{"source_write_guard.go", "AuthorizeSourceBranchUpsert", "ActionSourceBranchesUpsert"},
		{"source_write_guard.go", "AuthorizePullRequestRecording", "ActionPullRequestsRecord"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "../integration/app/"+tc.path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != tc.function {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				name, ok := call.Fun.(*ast.Ident)
				if !ok || name.Name != "prepareSourceWrite" && name.Name != "authorizeSourceWriteRepository" {
					return true
				}
				calls++
				index := 2
				if name.Name == "authorizeSourceWriteRepository" {
					index = 3
				}
				if len(call.Args) <= index {
					t.Errorf("%s.%s lacks typed action", tc.path, tc.function)
					return true
				}
				action, ok := call.Args[index].(*ast.SelectorExpr)
				if !ok || action.Sel.Name != tc.action {
					t.Errorf("%s.%s selects another operation", tc.path, tc.function)
				}
				return true
			})
		}
		if calls == 0 {
			t.Errorf("%s.%s has no covered authorization calls", tc.path, tc.function)
		}
	}
}

func TestSourcePoliciesHaveNoLocalActorGrantDecisions(t *testing.T) {
	for _, path := range []string{"../integration/query/source_write_authorizer.go", "../integration/query/source_repositories.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		central := 0
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope" {
				t.Errorf("%s retains local grant policy", path)
			}
			if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "authz" && (selector.Sel.Name == "Authorize" || selector.Sel.Name == "ReadVisibility") {
				central++
			}
			return true
		})
		if central == 0 {
			t.Errorf("%s has no central policy call", path)
		}
	}
}

func TestSourceRequestCallersHaveNoScopeFallback(t *testing.T) {
	for _, path := range []string{"source_repository_commands.go", "source_write_guard.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), "../integration/app/"+path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		requests := 0
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typ, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || typ.Sel.Name != "AuthorizationRequest" {
				return true
			}
			requests++
			action := false
			for _, element := range literal.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if name, ok := field.Key.(*ast.Ident); ok {
					if name.Name == "Scope" {
						t.Errorf("%s retains scope-string caller", path)
					}
					if name.Name == "Action" {
						action = true
					}
				}
			}
			if !action {
				t.Errorf("%s has an untyped request", path)
			}
			return true
		})
		if requests == 0 {
			t.Errorf("%s has no covered authorization requests", path)
		}
	}
}
