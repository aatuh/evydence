package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestIdentityMetadataListsUseOnlyFocusedQueries(t *testing.T) {
	for _, tc := range []struct{ file, handler, query string }{
		{"router.go", "listAPIKeys", "apiKeyQuery"},
		{"identity_handlers.go", "listRoleBindings", "roleBindingQuery"},
	} {
		t.Run(tc.handler, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tc.file, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			found, queries := false, 0
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != tc.handler {
					continue
				}
				found = true
				ast.Inspect(function.Body, func(node ast.Node) bool {
					selector, ok := node.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if owner, ok := selector.X.(*ast.Ident); ok && owner.Name == "s" {
						switch selector.Sel.Name {
						case "ledger", "identityAccess", "writeCreatedAtPaginated":
							t.Errorf("%s retains broad identity metadata reads", tc.handler)
						case tc.query:
							queries++
						}
					}
					return true
				})
			}
			if !found || queries != 1 {
				t.Errorf("%s found=%t focused references=%d, want true and one", tc.handler, found, queries)
			}
		})
	}
}
