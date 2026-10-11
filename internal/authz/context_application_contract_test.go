package authz_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseEvidenceAndRiskApplicationsHaveNoScopeRequestFallback(t *testing.T) {
	for _, context := range []string{"release", "evidence", "risk"} {
		dir := "../" + context + "/app"
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		files := 0
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
				continue
			}
			files++
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok && len(call.Args) > 2 {
					if method, ok := call.Fun.(*ast.SelectorExpr); ok && (method.Sel.Name == "authorize" || method.Sel.Name == "authorizeCatalog") {
						if value, ok := call.Args[2].(*ast.Ident); ok && strings.HasPrefix(value.Name, "Scope") {
							t.Errorf("%s/%s passes a scope constant as a typed action", context, name)
						}
					}
				}
				if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope" || selector.Sel.Name == "ResourceGrants") {
					t.Errorf("%s/%s retains local actor policy", context, name)
				}
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				typ, ok := literal.Type.(*ast.SelectorExpr)
				if !ok || typ.Sel.Name != "AuthorizationRequest" {
					return true
				}
				for _, element := range literal.Elts {
					if field, ok := element.(*ast.KeyValueExpr); ok {
						if key, ok := field.Key.(*ast.Ident); ok && key.Name == "Scope" {
							t.Errorf("%s/%s retains scope request fallback", context, name)
						}
					}
				}
				return true
			})
		}
		if files == 0 {
			t.Fatal("source guard matched no context application files", context)
		}
	}
}
