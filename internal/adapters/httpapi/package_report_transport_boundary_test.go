package httpapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestPackageReportAndBundleReadsHaveNoAggregateOrOptionalQueryPath(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for handler, port := range map[string]string{
		"missingEvidenceReport":          "missingEvidenceQuery",
		"controlCoverageReport":          "controlCoverageQuery",
		"craReadinessReport":             "controlCoverageQuery",
		"craVulnerabilityHandlingReport": "craVulnerabilityQuery",
		"securityUpdateEvidenceReport":   "securityUpdateEvidenceQuery",
		"getReleaseBundle":               "releaseBundleQuery",
		"getReleaseBundleManifest":       "releaseBundleQuery",
	} {
		found, reads := false, 0
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
				case "ledger", "create", "createWithActorFingerprint":
					t.Errorf("%s retains aggregate path %s", handler, selector.Sel.Name)
				case port:
					reads++
				}
				return true
			})
		}
		if !found || reads != 1 {
			t.Errorf("%s found=%t focused references=%d, want true/1", handler, found, reads)
		}
	}
}

func TestPackageReportOpenAPIDescriptionsRequirePostgresEvaluation(t *testing.T) {
	server, _ := testServer(t)
	body, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			Description string `json:"description"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/reports/missing-evidence", "/v1/reports/control-coverage", "/v1/reports/cra-readiness", "/v1/reports/cra-vulnerability-handling", "/v1/reports/security-update-evidence", "/v1/release-bundles/{id}", "/v1/release-bundles/{id}/manifest"} {
		description := doc.Paths[path]["get"].Description
		if !strings.Contains(description, "PostgreSQL is required for local evaluation.") {
			t.Errorf("%s omits the required evaluation backend", path)
		}
	}
}
