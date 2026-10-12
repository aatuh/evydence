package httpapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestSSOProviderHandlersHaveNoAggregateOrOptionalCommandPath(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "identity_handlers.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for handler, command := range map[string]string{"createSSOProvider": "createDurableSSOProvider", "updateSSOProviderTrustMaterial": "updateDurableSSOTrustMaterial", "refreshSSOProviderOIDCTrustMaterial": "refreshDurableSSOTrustMaterial", "linkSSOIdentity": "linkDurableSSOIdentity"} {
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
				if selector.Sel.Name == command {
					references++
				} else {
					t.Errorf("%s retains non-focused path %s", handler, selector.Sel.Name)
				}
				return true
			})
		}
		if !found || references != 1 {
			t.Errorf("%s found=%t native dispatches=%d, want true/1", handler, found, references)
		}
	}
	file, err = parser.ParseFile(token.NewFileSet(), "context_dependencies.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "identityAccessService" {
			return true
		}
		for _, method := range spec.Type.(*ast.InterfaceType).Methods.List {
			for _, name := range method.Names {
				switch name.Name {
				case "CreateSSOProvider", "UpdateSSOProviderTrustMaterial", "RefreshSSOProviderOIDCTrustMaterial", "LinkSSOIdentity":
					t.Errorf("broad identity port retains %s", name.Name)
				}
			}
		}
		return false
	})
}

func TestSSOProviderOpenAPIDescriptionsRequirePostgresEvaluation(t *testing.T) {
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
	for _, path := range []string{"/v1/sso/providers", "/v1/sso/providers/{id}/trust-material", "/v1/sso/providers/{id}/discover-oidc", "/v1/sso/identity-links"} {
		if !strings.Contains(doc.Paths[path]["post"].Description, "PostgreSQL is required for local evaluation.") {
			t.Errorf("%s omits required evaluation backend", path)
		}
	}
}
