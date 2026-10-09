package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestDeploymentCreationTransportUsesFocusedCommandsOnly(t *testing.T) {
	assertCatalogWriteComposition(t, "deployment_creation.go", []string{"createDeploymentEnvironment", "recordDeployment"})
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.TypeSpec:
				if value.Name.Name == "localDeploymentCommands" {
					t.Errorf("%s retains the broad deployment interface", name)
				}
			case *ast.Field:
				for _, field := range value.Names {
					if field.Name == "localDeployments" {
						t.Errorf("%s retains the broad deployment binding", name)
					}
				}
			case *ast.SelectorExpr:
				if value.Sel.Name == "localDeployments" {
					t.Errorf("%s accesses the broad deployment binding", name)
				}
			}
			return true
		})
	}
}

func TestDeploymentReadsUseOnlyFocusedQueries(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ handler, query string }{
		{"listDeploymentEnvironments", "deploymentListQuery"},
		{"listDeployments", "deploymentListQuery"},
		{"getDeployment", "deploymentPointQuery"},
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
					selector, ok := node.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					owner, ok := selector.X.(*ast.Ident)
					if !ok || owner.Name != "s" {
						return true
					}
					switch selector.Sel.Name {
					case "ledger", "localDeployments", "writeCreatedAtPaginated":
						t.Errorf("%s retains aggregate query fallback %s", tc.handler, selector.Sel.Name)
					case tc.query:
						focused++
					}
					return true
				})
			}
			if !found || focused != 1 {
				t.Errorf("%s found=%t focused references=%d, want true and one", tc.handler, found, focused)
			}
		})
	}
}
