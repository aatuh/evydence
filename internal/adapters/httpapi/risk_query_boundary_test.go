package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestRiskQueryTransportRequiresFocusedPorts(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ handler, port string }{
		{"listVulnerabilityDecisions", "vulnerabilityDecisionQuery"},
		{"vulnerabilityDecisionSummaryReport", "vulnerabilityDecisionSummaryQuery"},
		{"listExceptions", "exceptionsQuery"},
	} {
		t.Run(tc.handler, func(t *testing.T) {
			found, focused := false, 0
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != tc.handler {
					continue
				}
				found = true
				ast.Inspect(function.Body, func(node ast.Node) bool {
					if call, ok := node.(*ast.CallExpr); ok {
						if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "writeCreatedAtPaginated" {
							t.Errorf("%s retains inventory pagination", tc.handler)
						}
					}
					selector, ok := node.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					owner, ok := selector.X.(*ast.Ident)
					if !ok || owner.Name != "s" {
						return true
					}
					switch selector.Sel.Name {
					case "ledger", "riskDecisions", "writeCreatedAtPaginated":
						t.Errorf("%s retains broad risk query %s", tc.handler, selector.Sel.Name)
					case tc.port:
						focused++
					}
					return true
				})
			}
			if !found || focused != 1 {
				t.Errorf("%s found=%t focused references=%d, want true/1", tc.handler, found, focused)
			}
		})
	}
	file, err = parser.ParseFile(token.NewFileSet(), "context_dependencies.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "riskDecisionService" {
			return true
		}
		iface, ok := spec.Type.(*ast.InterfaceType)
		if !ok {
			t.Fatal("broad Risk dependency is not an interface")
		}
		for _, field := range iface.Methods.List {
			for _, name := range field.Names {
				switch name.Name {
				case "ListVulnerabilityDecisions", "VulnerabilityDecisionSummaryReport", "ListExceptions":
					t.Errorf("broad Risk interface retains retired query %s", name.Name)
				}
			}
		}
		return false
	})
}
