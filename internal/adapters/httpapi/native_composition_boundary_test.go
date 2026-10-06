package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestNativeCompositionCoreDoesNotAcceptOrConstructLedger(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	legacyAlias := "app"
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if path == "github.com/aatuh/evydence/internal/app" && spec.Name != nil {
			legacyAlias = spec.Name.Name
		}
	}
	found := false
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "newServerWithOptionsContext" {
			continue
		}
		found = true
		ast.Inspect(function, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			qualifier, ok := selector.X.(*ast.Ident)
			if ok && qualifier.Name == legacyAlias && (selector.Sel.Name == "Ledger" || selector.Sel.Name == "NewLedger" || selector.Sel.Name == "NewLedgerWithContext") {
				t.Errorf("native composition core retains %s.%s", qualifier.Name, selector.Sel.Name)
			}
			if selector.Sel.Name == "bindLedger" {
				t.Error("native composition core binds a legacy aggregate")
			}
			return true
		})
		for _, field := range function.Type.Params.List {
			for _, name := range field.Names {
				if name.Name == "local" {
					t.Error("native composition core still selects a legacy local path")
				}
			}
		}
	}
	if !found {
		t.Fatal("native composition core was not inspected")
	}
}

func TestLocalConstructorKeepsExplicitAuthenticatorAfterLegacyBinding(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{})
	authenticator := &configuredAuthenticator{}
	server, err := NewServerWithOptionsContext(t.Context(), ledger, ServerOptions{Authenticator: authenticator})
	if err != nil || server.ledger != ledger || server.authn != authenticator || server.idempotency == nil {
		t.Fatalf("local constructor lost explicit auth or compatibility binding: %v", err)
	}
}
