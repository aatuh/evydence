package httpapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestOperatorHandlersHaveNoAggregateOrOptionalPortPath(t *testing.T) {
	for source, handlers := range map[string]map[string]string{
		"system_handlers.go":   {"ready": "readinessQuery", "readinessDiagnostics": "readinessQuery", "metrics": "metricsQuery"},
		"identity_handlers.go": {"instanceAdminSnapshot": "instanceAdminQuery", "outboxOperatorDiagnostics": "outboxDiagnosticsQuery", "replayTerminalOutboxJob": "outboxReplayCommand"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), source, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for handler, port := range handlers {
			found, references := false, 0
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
						references++
					}
					return true
				})
			}
			if !found || references != 1 {
				t.Errorf("%s found=%t focused references=%d, want true/1", handler, found, references)
			}
		}
	}
}

func TestOperatorOpenAPIDescriptionsRequirePostgresEvaluation(t *testing.T) {
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
		"/v1/ready": "get", "/v1/admin/readiness": "get", "/v1/metrics": "get",
		"/v1/admin/instance": "get", "/v1/admin/outbox": "get", "/v1/admin/outbox/{id}/replay": "post",
	} {
		if !strings.Contains(doc.Paths[path][method].Description, "PostgreSQL is required for local evaluation.") {
			t.Errorf("%s omits the required evaluation backend", path)
		}
	}
}
