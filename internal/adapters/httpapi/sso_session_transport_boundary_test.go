package httpapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

func TestSSOSessionTransportHasNoBroadIdentityOrOptionalCommandPath(t *testing.T) {
	if _, found := reflect.TypeOf(Server{}).FieldByName("identityAccess"); found {
		t.Error("Server retains broad identity binding")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "identity_handlers.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for handler, port := range map[string]string{"createSSOSession": "createDurableSSOSession", "exchangeSSOCredential": "ssoExchangeCommands", "revokeSSOSession": "revokeDurableSSOSession", "logoutSSOSession": "logoutDurableSSOSession"} {
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
				if selector.Sel.Name == port {
					references++
				} else {
					t.Errorf("%s retains non-focused transport path %s", handler, selector.Sel.Name)
				}
				return true
			})
		}
		if !found || references != 1 {
			t.Errorf("%s found=%t focused references=%d, want true/1", handler, found, references)
		}
	}
	file, err = parser.ParseFile(token.NewFileSet(), "context_dependencies.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if ok && spec.Name.Name == "identityAccessService" {
			t.Error("broad identity transport interface remains")
		}
		return true
	})
}

func TestSSOSessionOpenAPIDescriptionsRequirePostgresEvaluation(t *testing.T) {
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
	for _, path := range []string{"/v1/sso/sessions", "/v1/sso/session-exchanges", "/v1/sso/sessions/{id}/revoke", "/v1/sso/logout"} {
		if !strings.Contains(doc.Paths[path]["post"].Description, "PostgreSQL is required for local evaluation.") {
			t.Errorf("%s omits required evaluation backend", path)
		}
	}
}
