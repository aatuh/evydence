package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestEvidenceReadTransportRequiresFocusedQueries(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for handler, port := range map[string]string{
		"listEvidence": "evidencePageQuery", "searchEvidence": "evidencePageQuery",
		"getEvidence": "evidencePointQuery", "listEvidenceLifecycleEvents": "lifecycleEventsQuery",
		"getSBOM": "sbomPointQuery", "listSBOMComponents": "sbomComponentsQuery",
		"getVulnerabilityScan": "vulnerabilityScanPointQuery", "getOpenAPIContract": "openAPIContractPointQuery",
		"getVEX": "vexPointQuery", "getVEXImportReport": "vexPointQuery",
		"previewVEXImport": "previewDurableVEX", "previewCycloneDXVEXImport": "previewDurableVEX",
	} {
		t.Run(handler, func(t *testing.T) {
			found, calls := false, 0
			for _, declaration := range file.Decls {
				fn, ok := declaration.(*ast.FuncDecl)
				if !ok || fn.Name.Name != handler {
					continue
				}
				found = true
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					if branch, ok := node.(*ast.IfStmt); ok {
						ast.Inspect(branch.Cond, func(node ast.Node) bool {
							selector, ok := node.(*ast.SelectorExpr)
							if ok {
								if owner, ok := selector.X.(*ast.Ident); ok && owner.Name == "s" && (selector.Sel.Name == port || selector.Sel.Name == "vexPreviewQuery") {
									t.Error("focused query remains optional")
								}
							}
							return true
						})
					}
					selector, ok := node.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					owner, ok := selector.X.(*ast.Ident)
					if !ok || owner.Name != "s" {
						return true
					}
					if selector.Sel.Name == "ledger" || selector.Sel.Name == "evidenceIngestion" {
						t.Error("handler retains a broad evidence read dependency")
					}
					if selector.Sel.Name == port {
						calls++
					}
					return true
				})
			}
			if !found || calls != 1 {
				t.Errorf("handler found=%t focused references=%d, want true/1", found, calls)
			}
		})
	}
	dependencies, err := parser.ParseFile(token.NewFileSet(), "context_dependencies.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(dependencies, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "evidenceIngestionService" {
			return true
		}
		iface := spec.Type.(*ast.InterfaceType)
		for _, field := range iface.Methods.List {
			for _, name := range field.Names {
				switch name.Name {
				case "ListEvidencePage", "SearchEvidencePage", "GetEvidence", "ListEvidenceLifecycleEvents", "GetSBOM", "ListSBOMComponents", "PreviewVEXImport", "GetVEXDocument", "GetVEXImportReport", "PreviewCycloneDXVEXImport", "GetVulnerabilityScan", "GetOpenAPIContract", "CreateEvidence", "SupersedeEvidence", "LinkEvidence", "RecordEvidenceLifecycleEvent":
					t.Errorf("broad interface retains retired method %s", name.Name)
				}
			}
		}
		return false
	})
}
