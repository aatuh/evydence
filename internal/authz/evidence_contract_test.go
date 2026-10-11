package authz_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestEvidenceQueryGrantDecisionsAreCentral(t *testing.T) {
	for _, path := range []string{"../evidence/query/creation_authorizer.go", "../evidence/query/evidence_points.go", "../evidence/query/sbom_components.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		central := 0
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope" {
				t.Errorf("%s retains local grant policy: %s", path, selector.Sel.Name)
			}
			if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "authz" && (selector.Sel.Name == "Authorize" || selector.Sel.Name == "ReadVisibility") {
				central++
			}
			return true
		})
		if central == 0 {
			t.Fatalf("%s has no central policy call", path)
		}
	}
}

func TestEvidenceReadCallersSelectOwnRegisteredAction(t *testing.T) {
	for _, tc := range []struct{ path, action string }{
		{"evidence_points.go", "ActionEvidenceRead"}, {"evidence_pages.go", "ActionEvidenceRead"},
		{"sbom_points.go", "ActionSBOMsRead"}, {"vex_points.go", "ActionVEXDocumentsRead"},
		{"openapi_contract_points.go", "ActionOpenAPIContractsRead"}, {"vulnerability_scan_points.go", "ActionVulnerabilityScansRead"},
		{"lifecycle_events.go", "ActionEvidenceLifecycleRead"}, {"sbom_components.go", "ActionSBOMComponentsRead"},
		{"vex_preview.go", "ActionVEXPreviewRead"}, {"diff_authorizer.go", "ActionEvidenceDiffsCreate"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "../evidence/query/"+tc.path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || name.Name != "authorizeEvidenceRead" {
				return true
			}
			calls++
			if len(call.Args) != 5 {
				t.Errorf("%s untyped read contract", tc.path)
				return true
			}
			action, ok := call.Args[2].(*ast.SelectorExpr)
			if !ok || action.Sel.Name != tc.action {
				t.Errorf("%s selected another operation", tc.path)
			}
			return true
		})
		if calls == 0 {
			t.Fatalf("%s read-action coverage disappeared", tc.path)
		}
	}
}
