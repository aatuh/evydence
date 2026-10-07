package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestRiskCommandTransportHasNoBroadDependencyOrFallback(t *testing.T) {
	for _, name := range []string{"router.go", "context_dependencies.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.TypeSpec:
				if value.Name.Name == "riskDecisionService" {
					t.Error("retired broad Risk interface still exists")
				}
			case *ast.Field:
				for _, field := range value.Names {
					if field.Name == "riskDecisions" {
						t.Error("retired broad Risk Server binding still exists")
					}
				}
			}
			return true
		})
		for handler, delegate := range map[string]string{
			"createVulnerabilityDecision": "createDurableVulnerabilityDecision",
			"evaluatePolicy":              "evaluateDurablePolicy",
		} {
			if name != "router.go" {
				continue
			}
			found, delegated := false, 0
			for _, declaration := range file.Decls {
				fn, ok := declaration.(*ast.FuncDecl)
				if !ok || fn.Name.Name != handler {
					continue
				}
				found = true
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					selector, ok := node.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					owner, ok := selector.X.(*ast.Ident)
					if !ok || owner.Name != "s" {
						return true
					}
					switch selector.Sel.Name {
					case "ledger", "riskDecisions", "create", "createWithActor", "vulnerabilityDecisionCommands", "policyEvaluationCommands":
						t.Errorf("%s retains broad or optional path %s", handler, selector.Sel.Name)
					case delegate:
						delegated++
					}
					return true
				})
			}
			if !found || delegated != 1 {
				t.Errorf("%s found=%t delegates=%d, want true/1", handler, found, delegated)
			}
		}
	}
}
