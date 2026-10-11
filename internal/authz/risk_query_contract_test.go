package authz_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestRiskQueriesUseCentralPolicyAndDoNotReevaluateActorGrants(t *testing.T) {
	for _, path := range []string{
		"../risk/query/vulnerability_decisions.go", "../risk/query/exceptions.go", "../risk/query/control_evidence.go",
		"../risk/query/vulnerability_decision_summary.go", "../risk/query/release_readiness.go",
		"../risk/query/release_security_summary.go", "../risk/query/controls.go",
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
				t.Errorf("%s local grant policy: %s", path, selector.Sel.Name)
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
