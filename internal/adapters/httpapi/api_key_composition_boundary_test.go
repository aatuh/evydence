package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestAPIKeyCreationTransportHasNoAggregateFallback(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	found, focused := false, 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "createAPIKey" {
			continue
		}
		found = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			owner, ok := selector.X.(*ast.Ident)
			if !ok || owner.Name != "s" {
				return true
			}
			switch selector.Sel.Name {
			case "ledger", "identityAccess", "idempotency", "create", "apiKeyCommands":
				t.Errorf("API-key creation retains aggregate/capability fallback %s", selector.Sel.Name)
			case "createDurableAPIKey":
				focused++
			}
			return true
		})
	}
	if !found || focused != 1 {
		t.Fatalf("API-key handler found=%t focused references=%d, want true and one", found, focused)
	}
	file, err = parser.ParseFile(token.NewFileSet(), "context_dependencies.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "identityAccessService" {
			return true
		}
		iface, ok := typeSpec.Type.(*ast.InterfaceType)
		if !ok {
			t.Fatal("identity access is not an interface")
		}
		for _, field := range iface.Methods.List {
			for _, name := range field.Names {
				if name.Name == "CreateAPIKey" {
					t.Error("broad identity interface retains credential creation")
				}
			}
		}
		return false
	})
}
