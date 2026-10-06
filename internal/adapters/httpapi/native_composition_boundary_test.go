package httpapi

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

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

func TestLocalConstructorsRequireExplicitLedger(t *testing.T) {
	for name, construct := range map[string]func() (*Server, error){
		"default": func() (*Server, error) { return NewServer(nil) },
		"options": func() (*Server, error) {
			return NewServerWithOptions(nil, ServerOptions{})
		},
		"context": func() (*Server, error) {
			return NewServerWithOptionsContext(t.Context(), nil, ServerOptions{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			server, err := construct()
			if server != nil || err == nil || err.Error() != "local server requires an explicit Ledger" {
				t.Fatalf("implicit local aggregate accepted: server present=%t err=%v", server != nil, err)
			}
		})
	}
}

func TestLocalConstructorRejectsInvalidContextBeforeComposition(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{})
	var missingContext context.Context
	if server, err := NewServerWithOptionsContext(missingContext, ledger, ServerOptions{}); server != nil || err == nil || err.Error() != "server context is required" {
		t.Fatalf("missing context accepted: server present=%t err=%v", server != nil, err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, cancelDeadline := context.WithDeadline(t.Context(), time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC))
	defer cancelDeadline()
	for _, test := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{name: "canceled", ctx: canceled, want: context.Canceled},
		{name: "expired", ctx: expired, want: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, dependency := range []*app.Ledger{nil, ledger} {
				server, err := NewServerWithOptionsContext(test.ctx, dependency, ServerOptions{})
				if server != nil || !errors.Is(err, test.want) {
					t.Fatalf("inactive context did not stop composition: server present=%t err=%v", server != nil, err)
				}
			}
		})
	}
}

func TestLocalConstructorRequiresLedgerBeforeValidatingServiceOptions(t *testing.T) {
	server, err := NewServerWithOptionsContext(t.Context(), nil, ServerOptions{APIKeyCommands: &apiKeyHTTPFake{}})
	if server != nil || err == nil || err.Error() != "local server requires an explicit Ledger" {
		t.Fatalf("missing Ledger reached option composition: server present=%t err=%v", server != nil, err)
	}
}

func ledgerConstructionSelector(node ast.Node, alias string) bool {
	if call, ok := node.(*ast.CallExpr); ok && len(call.Args) == 1 {
		if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "new" {
			if sel, ok := call.Args[0].(*ast.SelectorExpr); ok && sel.Sel.Name == "Ledger" {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == alias {
					return true
				}
			}
		}
	}
	if composite, ok := node.(*ast.CompositeLit); ok {
		if sel, ok := composite.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Ledger" {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == alias {
				return true
			}
		}
	}
	sel, ok := node.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == alias && (sel.Sel.Name == "NewLedger" || sel.Sel.Name == "NewLedgerWithContext")
}

func TestLedgerConstructionScannerRecognizesFactoriesAndAllocations(t *testing.T) {
	for _, test := range []struct {
		expression string
		alias      string
		want       bool
	}{
		{expression: "app.NewLedger(cfg)", alias: "app", want: true},
		{expression: "legacy.NewLedgerWithContext(ctx, cfg)", alias: "legacy", want: true},
		{expression: "app.Ledger{}", alias: "app", want: true},
		{expression: "&legacy.Ledger{}", alias: "legacy", want: true},
		{expression: "new(app.Ledger)", alias: "app", want: true},
		{expression: "(*app.Ledger)(nil)", alias: "app", want: false},
		{expression: "other.NewLedger(cfg)", alias: "app", want: false},
		{expression: "app.Config{}", alias: "app", want: false},
	} {
		t.Run(test.expression, func(t *testing.T) {
			expression, err := parser.ParseExpr(test.expression)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			ast.Inspect(expression, func(node ast.Node) bool {
				found = found || ledgerConstructionSelector(node, test.alias)
				return true
			})
			if found != test.want {
				t.Fatalf("construction detected=%t, want %t", found, test.want)
			}
		})
	}
}

func TestHTTPTransportCannotConstructLedger(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		alias := ""
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if path == "github.com/aatuh/evydence/internal/app" {
				alias = "app"
				if spec.Name != nil {
					alias = spec.Name.Name
				}
				if alias == "." {
					t.Fatalf("%s obscures aggregate construction with a dot import", name)
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if ledgerConstructionSelector(node, alias) {
				t.Errorf("%s constructs a Ledger inside HTTP transport", name)
			}
			return true
		})
	}
}
