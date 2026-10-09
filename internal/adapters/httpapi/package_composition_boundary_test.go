package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestReportTemplateAndBundleTransportRequireFocusedPorts(t *testing.T) {
	assertCatalogWriteComposition(t, "report_template_commands.go", []string{"createReportTemplate", "renderReportTemplate"})
	assertCatalogWriteComposition(t, "bundle_import_command.go", []string{"importEvidenceBundle"})
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
				switch value.Name.Name {
				case "localReportTemplateCommands", "localBundleImportCommand", "localEvidenceBundleCommands":
					t.Errorf("%s retains broad package interface %s", name, value.Name.Name)
				}
			case *ast.Field:
				for _, field := range value.Names {
					switch field.Name {
					case "localReportTemplates", "localBundleImport", "localEvidenceBundles":
						t.Errorf("%s retains broad package binding %s", name, field.Name)
					}
				}
			case *ast.SelectorExpr:
				switch value.Sel.Name {
				case "localReportTemplates", "localBundleImport", "localEvidenceBundles":
					t.Errorf("%s accesses broad package binding %s", name, value.Sel.Name)
				}
			}
			return true
		})
	}
	file, err := parser.ParseFile(token.NewFileSet(), "evidence_bundle_export.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	found, focused := false, 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "exportEvidenceBundle" {
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
			case "ledger", "packages", "idempotency", "create", "createWithActorFingerprintAndResponseGuard":
				t.Errorf("bundle export retains aggregate executor %s", selector.Sel.Name)
			case "executeDurableCreate":
				focused++
			}
			return true
		})
	}
	if !found || focused != 1 {
		t.Fatalf("bundle export found=%t focused references=%d, want true and one", found, focused)
	}
}
