package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Complementary to live bootstrap/replay tests: no API entry-point branch may
// retain the aggregate or its local bootstrap, including development startup.
func TestStartupUsesNativeServicesAndDurableBootstrapWithoutLedger(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var run *ast.FuncDecl
	for _, declaration := range file.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == "runWithContext" {
			run = fn
		}
	}
	if run == nil {
		t.Fatal("API startup function is missing")
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "NewLedger", "NewLedgerWithContext", "HasTenants", "BootstrapTenant", "NewServer", "NewServerWithOptions", "NewServerWithOptionsContext":
			t.Errorf("API entry point retains legacy selector %s", selector.Sel.Name)
		case "Config", "Ledger":
			if owner, ok := selector.X.(*ast.Ident); ok && owner.Name == "app" {
				t.Errorf("API entry point retains aggregate type app.%s", selector.Sel.Name)
			}
		}
		return true
	})
	positions := map[string]token.Pos{}
	counts := map[string]int{}
	ast.Inspect(run.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		name := ""
		if ok {
			name = selector.Sel.Name
		} else if id, ok := call.Fun.(*ast.Ident); ok {
			name = id.Name
		}
		switch name {
		case "ResolveRuntimeProfile", "OpenRuntime", "BuildTenantBootstrapCommands", "BootstrapFirstTenant", "writeTenantBootstrapResult", "BuildAPIReadServices", "NewNativeServerWithOptionsContext":
			counts[name]++
			positions[name] = call.Pos()
		}
		return true
	})
	sequence := []string{"ResolveRuntimeProfile", "OpenRuntime", "BuildTenantBootstrapCommands", "BootstrapFirstTenant", "writeTenantBootstrapResult", "BuildAPIReadServices", "NewNativeServerWithOptionsContext"}
	var previous token.Pos
	for _, name := range sequence {
		if counts[name] != 1 || positions[name] <= previous {
			t.Fatalf("startup binding %s: count=%d, ordering invalid=%t", name, counts[name], positions[name] <= previous)
		}
		previous = positions[name]
	}
	var enablesBootstrap func(ast.Expr) bool
	enablesBootstrap = func(expr ast.Expr) bool {
		switch value := expr.(type) {
		case *ast.ParenExpr:
			return enablesBootstrap(value.X)
		case *ast.UnaryExpr:
			id, ok := value.X.(*ast.Ident)
			return ok && value.Op == token.NOT && id.Name == "bootstrapDisabled"
		case *ast.BinaryExpr:
			return value.Op == token.LAND && (enablesBootstrap(value.X) || enablesBootstrap(value.Y))
		}
		return false
	}
	guarded := false
	ast.Inspect(run.Body, func(node ast.Node) bool {
		branch, ok := node.(*ast.IfStmt)
		if !ok || !enablesBootstrap(branch.Cond) {
			return true
		}
		ast.Inspect(branch.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "BootstrapFirstTenant" {
				guarded = true
			}
			return true
		})
		return true
	})
	if !guarded {
		t.Fatal("durable bootstrap no longer honors EVYDENCE_BOOTSTRAP_DISABLED")
	}
}
