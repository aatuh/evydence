package httpapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestControlTransportHasNoAggregateFallbackOrInputMapper(t *testing.T) {
	for path, handlers := range map[string][]string{
		"router.go":                    {"listControlFrameworks", "listControlFrameworkTemplatePacks", "getSecurityControl", "listControlEvidence"},
		"control_commands.go":          {"createControlFramework", "createSecurityControl"},
		"control_template_commands.go": {"installControlFrameworkTemplatePack"},
		"control_evidence_commands.go": {"linkControlEvidence"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range handlers {
			found := false
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				switch fn.Name.Name {
				case "localControlFrameworkInput", "localSecurityControlInput", "localControlEvidenceInput":
					t.Errorf("aggregate input mapper %s remains", fn.Name.Name)
				}
				if fn.Name.Name != name {
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
						case "controlCommands", "controlTemplateCommands", "controlEvidenceCommands", "controlsQuery", "controlTemplateQuery", "controlEvidenceQuery":
							t.Errorf("%s retains optional dependency branch %s", name, selector.Sel.Name)
						}
						return true
					})
					return true
				})
			}
			if !found {
				t.Errorf("%s missing in %s", name, path)
			}
		}
	}
}

func TestControlOpenAPIDescriptionsRequirePostgresLocalEvaluation(t *testing.T) {
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
	for _, path := range []string{"/v1/control-frameworks", "/v1/controls", "/v1/controls/{id}/evidence", "/v1/control-framework-template-packs/{slug}/install"} {
		description := doc.Paths[path]["post"].Description
		if !strings.Contains(description, "PostgreSQL is required for local evaluation.") {
			t.Errorf("%s omits the supported evaluation requirement", path)
		}
		for _, retired := range []string{"Local memory", "Local-memory", "local_memory", "both profiles"} {
			if strings.Contains(description, retired) {
				t.Errorf("%s advertises the retired runtime: %s", path, retired)
			}
		}
	}
}
