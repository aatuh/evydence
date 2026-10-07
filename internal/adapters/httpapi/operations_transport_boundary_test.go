package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestOperationsTransportHasNoAggregateFallback(t *testing.T) {
	for path, handlers := range map[string][]string{
		"router.go":                    {"createIncident", "recordIncidentTimeline", "createIncidentWebhookReceiver", "receiveIncidentWebhook", "createRemediationTask", "incidentReport"},
		"retention_marker_commands.go": {"createRetentionMarker"},
		"ops_handlers.go":              {"retentionReport"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range handlers {
			found := false
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != name {
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
						t.Errorf("%s retains aggregate path %s", name, selector.Sel.Name)
					}
					return true
				})
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					branch, ok := node.(*ast.IfStmt)
					if !ok {
						return true
					}
					ast.Inspect(branch.Cond, func(node ast.Node) bool {
						selector, ok := node.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						switch selector.Sel.Name {
						case "incidentCommands", "incidentWebhookCommands", "incidentReportQuery", "retentionMarkerCommands", "retentionQuery":
							t.Errorf("%s retains optional dependency branch %s", name, selector.Sel.Name)
						}
						return true
					})
					return true
				})
			}
			if !found {
				t.Errorf("%s not found in %s", name, path)
			}
		}
	}
}
