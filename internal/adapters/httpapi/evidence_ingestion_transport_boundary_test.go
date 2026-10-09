package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestEvidenceIngestionTransportHasNoBroadDependencyOrFallback(t *testing.T) {
	for _, path := range []string{"router.go", "context_dependencies.go", "ingestion_handlers.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.FuncDecl:
				if value.Name.Name == "createStreamedEvidence" {
					t.Error("retired aggregate streamed wrapper still exists")
				}
			case *ast.TypeSpec:
				if value.Name.Name == "evidenceIngestionService" {
					t.Error("retired broad Evidence interface still exists")
				}
			case *ast.Field:
				for _, name := range value.Names {
					if name.Name == "evidenceIngestion" {
						t.Error("retired broad Evidence Server binding still exists")
					}
				}
			}
			return true
		})
		if path != "router.go" {
			continue
		}
		for handler, delegate := range map[string]string{
			"uploadSecurityScan": "uploadDurableSecurityScan", "uploadAPISecurityScan": "uploadDurableSecurityScan",
			"uploadManualSecurityDocument": "uploadDurableManualSecurityDocument",
			"uploadSPDXSBOM":               "uploadDurableSBOM", "uploadSBOM": "uploadDurableSBOM",
			"uploadVEX": "uploadDurableVEX", "uploadCycloneDXVEX": "uploadDurableVEX",
			"uploadVulnerabilityScan": "uploadDurableVulnerabilityScan", "uploadOpenAPIContract": "uploadDurableOpenAPIContract",
			"createSBOMDiff": "createDurableSBOMDiff", "createOpenAPIDiff": "createDurableContractDiff",
		} {
			found, delegated := false, 0
			for _, declaration := range file.Decls {
				fn, ok := declaration.(*ast.FuncDecl)
				if !ok || fn.Name.Name != handler {
					continue
				}
				found = true
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					selector, ok := node.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					owner, ok := selector.X.(*ast.Ident)
					if !ok || owner.Name != "s" {
						return true
					}
					switch selector.Sel.Name {
					case "ledger", "evidenceIngestion", "create", "createStreamedEvidence", "sbomIngestionCommands", "vexIngestionCommands", "scanIngestionCommands", "openAPIIngestionCommands", "securityDocumentCommands", "sbomDiffCommands", "contractDiffCommands":
						t.Errorf("%s retains broad or optional path %s", handler, selector.Sel.Name)
					case delegate:
						delegated++
					}
					return true
				})
			}
			if !found || delegated != 1 {
				t.Errorf("%s found=%t delegates=%d, want true/1", handler, found, delegated)
			}
		}
	}
}
