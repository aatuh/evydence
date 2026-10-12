package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestEvidenceCreationAndRelationshipsRequireFocusedCommands(t *testing.T) {
	assertCatalogWriteComposition(t, "evidence_creation_commands.go", []string{"createEvidence"})
	assertCatalogWriteComposition(t, "evidence_relationship_commands.go", []string{"supersedeEvidence", "linkEvidence", "recordEvidenceLifecycleEvent"})
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
				if value.Name.Name == "localEvidenceCreationCommands" || value.Name.Name == "localEvidenceRelationshipCommands" {
					t.Errorf("%s retains aggregate evidence interface %s", name, value.Name.Name)
				}
			case *ast.Field:
				for _, field := range value.Names {
					if field.Name == "localEvidenceCreation" || field.Name == "localEvidenceRelationships" {
						t.Errorf("%s retains aggregate evidence binding %s", name, field.Name)
					}
				}
			case *ast.SelectorExpr:
				if value.Sel.Name == "localEvidenceCreation" || value.Sel.Name == "localEvidenceRelationships" {
					t.Errorf("%s accesses aggregate evidence binding %s", name, value.Sel.Name)
				}
			}
			return true
		})
	}
}
