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
	startup, err := parser.ParseFile(token.NewFileSet(), "startup.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := map[string]*ast.FuncDecl{}
	signingConstructorBound := false
	for _, source := range []*ast.File{file, startup} {
		for _, declaration := range source.Decls {
			if fn, ok := declaration.(*ast.FuncDecl); ok {
				functions[fn.Name.Name] = fn
			}
			if group, ok := declaration.(*ast.GenDecl); ok && group.Tok == token.VAR {
				for _, spec := range group.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok || len(value.Names) != 1 || value.Names[0].Name != "newAPISigningExecutor" || len(value.Values) != 1 {
						continue
					}
					constructor, ok := value.Values[0].(*ast.Ident)
					signingConstructorBound = ok && constructor.Name == "openSigningExecutorConfigured"
				}
			}
		}
	}
	if !signingConstructorBound {
		t.Fatal("production signing factory is not bound to its typed provider constructor")
	}
	run, entry, process := functions["runAPIConfigured"], functions["run"], functions["runAPIProcess"]
	if run == nil || entry == nil || process == nil {
		t.Fatal("typed API startup composition is missing")
	}
	var entryStages []string
	ast.Inspect(entry.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Capture" {
			entryStages = append(entryStages, "Capture")
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "runAPIProcess" {
			entryStages = append(entryStages, "runAPIProcess")
			callback, ok := call.Args[3].(*ast.Ident)
			if !ok || callback.Name != "runAPIConfigured" {
				t.Fatal("entry point bypasses typed runtime callback")
			}
		}
		return true
	})
	if len(entryStages) != 2 || entryStages[0] != "Capture" || entryStages[1] != "runAPIProcess" {
		t.Fatal("entry point does not capture once before shared startup")
	}
	var stages []string
	ast.Inspect(process.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "Prepare", "Resolve", "PreparePoolConfig":
			stages = append(stages, selector.Sel.Name)
		case "RunConfigured":
			stages = append(stages, selector.Sel.Name)
			callback, ok := call.Args[5].(*ast.FuncLit)
			if !ok || len(callback.Body.List) != 1 {
				t.Fatal("configured logging callback is missing")
			}
			statement, ok := callback.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(statement.Results) != 1 {
				t.Fatal("logging callback does not return runtime result")
			}
			invoke, ok := statement.Results[0].(*ast.CallExpr)
			if !ok {
				t.Fatal("runtime callback invocation is missing")
			}
			id, ok := invoke.Fun.(*ast.Ident)
			if !ok || id.Name != "start" || len(invoke.Args) != 3 {
				t.Fatal("typed runtime is outside configured lifecycle")
			}
		}
		return true
	})
	wanted := []string{"Prepare", "Resolve", "PreparePoolConfig", "RunConfigured"}
	if len(stages) != len(wanted) {
		t.Fatal("startup validation stage count changed")
	}
	for i, name := range wanted {
		if stages[i] != name {
			t.Fatal("API resources can start before complete preflight")
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "NewLedger", "NewLedgerWithContext", "HasTenants", "BootstrapTenant", "NewServer", "NewServerWithOptions", "NewServerWithOptionsContext":
			// BootstrapTenant is also the shared APISettings value field. Only
			// that field read in its typed projection is exempt from the ban on
			// legacy aggregate selectors (including escaped method values).
			projection := functions["tenantBootstrapInputFromSettings"]
			if selector.Sel.Name == "BootstrapTenant" && projection != nil && selector.Pos() >= projection.Body.Pos() && selector.End() <= projection.Body.End() {
				owner, field := selector.X.(*ast.Ident)
				parameter := projection.Type.Params.List[0]
				kind, typed := parameter.Type.(*ast.SelectorExpr)
				if field && owner.Name == "settings" && typed && kind.Sel.Name == "APISettings" {
					return true
				}
			}
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
		case "NewConfigured", "openProviderIdentityValidatorConfigured", "openTransparencyProofFetcherConfigured", "openCosignVerifierConfigured", "newAPISigningExecutor", "apiRuntimeConfigFromSettings", "OpenRuntime", "BuildTenantBootstrapCommands", "BootstrapFirstTenant", "writeTenantBootstrapResult", "BuildAPIReadServices", "NewNativeServerWithOptionsContext":
			counts[name]++
			positions[name] = call.Pos()
		}
		return true
	})
	sequence := []string{"NewConfigured", "openProviderIdentityValidatorConfigured", "openTransparencyProofFetcherConfigured", "openCosignVerifierConfigured", "newAPISigningExecutor", "apiRuntimeConfigFromSettings", "OpenRuntime", "BuildTenantBootstrapCommands", "BootstrapFirstTenant", "writeTenantBootstrapResult", "BuildAPIReadServices", "NewNativeServerWithOptionsContext"}
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
