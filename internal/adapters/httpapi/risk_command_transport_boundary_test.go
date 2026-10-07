package httpapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestRiskCommandTransportHasNoBroadDependencyOrFallback(t *testing.T) {
	for _, name := range []string{"router.go", "context_dependencies.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.TypeSpec:
				if value.Name.Name == "riskDecisionService" {
					t.Error("retired broad Risk interface still exists")
				}
			case *ast.Field:
				for _, field := range value.Names {
					if field.Name == "riskDecisions" {
						t.Error("retired broad Risk Server binding still exists")
					}
				}
			}
			return true
		})
		for handler, delegate := range map[string]string{
			"createVulnerabilityDecision": "createDurableVulnerabilityDecision",
			"evaluatePolicy":              "evaluateDurablePolicy",
			"recordVulnerabilityWorkflow": "recordDurableVulnerabilityWorkflow",
			"createCustomPolicy":          "createDurableCustomPolicy",
			"evaluateCustomPolicy":        "evaluateDurableCustomPolicy",
		} {
			if name != "router.go" {
				continue
			}
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
					case "ledger", "riskDecisions", "create", "createWithActor", "vulnerabilityDecisionCommands", "policyEvaluationCommands", "customPolicyCommands", "vulnerabilityWorkflowCommands":
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

func TestRiskWorkflowOpenAPIDescriptionsRequirePostgresEvaluation(t *testing.T) {
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
	for path, method := range map[string]string{
		"/v1/custom-policies":                      "post",
		"/v1/custom-policies/{id}/evaluate":        "post",
		"/v1/vulnerability-findings/{id}/workflow": "post",
		"/v1/releases/{id}/security-summary":       "get",
		"/v1/reports/vulnerability-posture":        "get",
	} {
		description := doc.Paths[path][method].Description
		if !strings.Contains(description, "PostgreSQL is required for local evaluation.") {
			t.Errorf("%s omits the required evaluation backend", path)
		}
		for _, retired := range []string{"local_memory", "Local memory", "Local-memory", "both profiles"} {
			if strings.Contains(description, retired) {
				t.Errorf("%s advertises the retired runtime", path)
			}
		}
	}
}

func TestRiskReportTransportHasNoAggregateOrOptionalQueryPath(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"releaseSecuritySummary", "vulnerabilityPostureReport"} {
		found := false
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Name.Name != name {
				continue
			}
			found = true
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if selector, ok := node.(*ast.SelectorExpr); ok {
					if owner, ok := selector.X.(*ast.Ident); ok && owner.Name == "s" && selector.Sel.Name == "ledger" {
						t.Errorf("%s retains aggregate report path", name)
					}
				}
				if branch, ok := node.(*ast.IfStmt); ok {
					ast.Inspect(branch.Cond, func(node ast.Node) bool {
						if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "releaseSecuritySummaryQuery" || selector.Sel.Name == "vulnerabilityPostureQuery") {
							t.Errorf("%s retains optional query dependency", name)
						}
						return true
					})
				}
				return true
			})
		}
		if !found {
			t.Errorf("missing report handler %s", name)
		}
	}
}
