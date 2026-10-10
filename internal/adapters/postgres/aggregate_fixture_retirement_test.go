package postgres

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestPostgresFixturesDoNotConstructOrAcceptAggregate(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	inspected := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		inspected++
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Ledger" && selector.Sel.Name != "NewLedgerWithContext" {
				return true
			}
			if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "app" {
				t.Errorf("%s still constructs or accepts the aggregate", entry.Name())
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no PostgreSQL fixtures inspected")
	}
}
