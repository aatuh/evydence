package authz_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestReleaseReadCallersSelectOwnActionAndDoNotInspectActorGrants(t *testing.T) {
	for _, tc := range []struct{ path, action string }{
		{"../release/query/products.go", "ActionProductsRead"},
		{"../release/query/release_candidates.go", "ActionReleaseCandidatesRead"},
		{"../release/query/artifact_points.go", "ActionArtifactsRead"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), tc.path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		actions, visibility := 0, 0
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope" {
				t.Errorf("%s retains local grant policy: %s", tc.path, selector.Sel.Name)
			}
			if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "authz" {
				if selector.Sel.Name == tc.action {
					actions++
				}
				if selector.Sel.Name == "ReadVisibility" {
					visibility++
				}
				if tc.action == "ActionReleaseCandidatesRead" && selector.Sel.Name == "ActionReleasesRead" {
					t.Errorf("%s still selects another operation's action", tc.path)
				}
			}
			return true
		})
		if actions == 0 || visibility == 0 {
			t.Errorf("%s lacks own action or central visibility", tc.path)
		}
	}
}
