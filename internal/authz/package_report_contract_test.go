package authz_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestPackageReportQueriesBindOwnActionsWithoutLocalGrantFallback(t *testing.T) {
	for _, tc := range []struct {
		path    string
		actions []string
	}{
		{"vulnerability_posture.go", []string{"ActionReleaseVulnerabilityPostureRead", "ActionVulnerabilityPostureRead"}},
		{"control_coverage_report.go", []string{"ActionControlCoverageReportRead", "ActionCRAReadinessReportRead"}},
		{"cra_vulnerability_handling.go", []string{"ActionCRAVulnerabilityHandlingRead"}},
		{"release_readiness_report.go", []string{"ActionReleaseReadinessReportRead"}},
		{"security_update_evidence.go", []string{"ActionSecurityUpdateEvidenceRead"}},
		{"incident_report.go", []string{"ActionIncidentReportRead"}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "../package/query/"+tc.path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil {
					continue
				}
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					if selector, ok := node.(*ast.SelectorExpr); ok {
						if selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope" {
							t.Error("report retains local actor grant policy", selector.Sel.Name)
						}
						if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "authz" && strings.HasPrefix(selector.Sel.Name, "Action") {
							seen[selector.Sel.Name] = true
						}
					}
					if call, ok := node.(*ast.CallExpr); ok {
						if name, ok := call.Fun.(*ast.Ident); ok && (name.Name == "releaseScopeAllowed" || name.Name == "releaseReportAllowed" || name.Name == "postureReleaseAllowed" || name.Name == "incidentReportAllowed") {
							t.Error("report retains legacy grant fallback", name.Name)
						}
					}
					return true
				})
			}
			for _, action := range tc.actions {
				if !seen[action] {
					t.Error("report lacks own registered action", action)
				}
			}
		})
	}
}
