package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// The retired wrappers merely held *Ledger and forwarded back into the same
// aggregate. They must not return as substitutes for context-owned services.
func TestLegacyLedgerServiceShellsAreRetired(t *testing.T) {
	retired := map[string]bool{
		"identityService":        true,
		"releaseEvidenceService": true,
		"packageReportService":   true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.TypeSpec:
				if retired[n.Name.Name] {
					t.Errorf("%s declares retired Ledger service shell %s", name, n.Name.Name)
				}
			case *ast.FuncDecl:
				if retired[n.Name.Name] || n.Name.Name == "NewLedger" || n.Name.Name == "ReleaseLedgerMutationFromState" {
					t.Errorf("%s declares retired Ledger helper %s", name, n.Name.Name)
				}
			case *ast.SelectorExpr:
				if retired[n.Sel.Name] {
					t.Errorf("%s calls retired Ledger service factory %s", name, n.Sel.Name)
				}
			}
			return true
		})
	}
}
