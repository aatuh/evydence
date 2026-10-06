package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// This is an architectural regression check, complementary to the live
// transaction tests in wiring. Production bootstrap must not silently regain
// a Ledger dependency while that aggregate is being retired.
func TestStartupRestrictsLedgerBootstrapToExplicitLocalMemory(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var run *ast.FuncDecl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "runWithContext" {
			run = f
		}
	}
	if run == nil {
		t.Fatal("API startup function is missing")
	}
	guardHasProfile := func(expr ast.Expr, name string) bool {
		var matches func(ast.Expr) bool
		matches = func(expr ast.Expr) bool {
			if p, ok := expr.(*ast.ParenExpr); ok {
				return matches(p.X)
			}
			b, ok := expr.(*ast.BinaryExpr)
			if !ok {
				return false
			}
			if b.Op == token.LAND {
				return matches(b.X) || matches(b.Y)
			}
			id, idOK := b.X.(*ast.Ident)
			selector, selectorOK := b.Y.(*ast.SelectorExpr)
			if b.Op != token.EQL || !idOK || id.Name != "profile" || !selectorOK || selector.Sel.Name != name {
				return false
			}
			owner, ok := selector.X.(*ast.Ident)
			return ok && owner.Name == "wiring"
		}
		return matches(expr)
	}
	legacyCalls, durableCalls, nativeConstructors := 0, 0, 0
	var ledgerConstruction, durableBootstrap token.Pos
	var inspect func(ast.Node, bool, bool)
	inspect = func(node ast.Node, local, durable bool) {
		ast.Inspect(node, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			if branch, ok := n.(*ast.SwitchStmt); ok {
				tag, isProfile := branch.Tag.(*ast.Ident)
				if isProfile && tag.Name == "profile" {
					if branch.Init != nil {
						inspect(branch.Init, local, durable)
					}
					for _, node := range branch.Body.List {
						clause := node.(*ast.CaseClause)
						localCase, durableCase := false, false
						// A mixed/default case does not guarantee either profile.
						if len(clause.List) == 1 {
							if value, ok := clause.List[0].(*ast.SelectorExpr); ok {
								if owner, ok := value.X.(*ast.Ident); ok && owner.Name == "wiring" {
									localCase, durableCase = value.Sel.Name == "LocalMemory", value.Sel.Name == "PostgreSQL"
								}
							}
						}
						for _, statement := range clause.Body {
							inspect(statement, local || localCase, durable || durableCase)
						}
					}
					return false
				}
			}
			if branch, ok := n.(*ast.IfStmt); ok {
				if branch.Init != nil {
					inspect(branch.Init, local, durable)
				}
				inspect(branch.Cond, local, durable)
				inspect(branch.Body, local || guardHasProfile(branch.Cond, "LocalMemory"), durable || guardHasProfile(branch.Cond, "PostgreSQL"))
				if branch.Else != nil {
					inspect(branch.Else, local, durable)
				}
				return false
			}
			if expr, ok := n.(*ast.BinaryExpr); ok && expr.Op == token.LAND {
				// The right operand runs only after its left guard is true;
				// checking a profile later is too late for a Ledger call.
				inspect(expr.X, local, durable)
				inspect(expr.Y, local || guardHasProfile(expr.X, "LocalMemory"), durable || guardHasProfile(expr.X, "PostgreSQL"))
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if selector.Sel.Name == "HasTenants" || selector.Sel.Name == "BootstrapTenant" {
				legacyCalls++
				if !local {
					t.Error("Ledger bootstrap is reachable outside explicit local-memory mode")
				}
			}
			if selector.Sel.Name == "BuildTenantBootstrapCommands" || selector.Sel.Name == "BootstrapFirstTenant" {
				durableCalls++
				if !durable {
					t.Error("durable bootstrap is not guarded by the PostgreSQL runtime profile")
				}
			}
			if selector.Sel.Name == "BootstrapFirstTenant" {
				durableBootstrap = call.Pos()
			}
			if selector.Sel.Name == "NewLedgerWithContext" {
				if !local {
					t.Error("Ledger construction is reachable outside explicit local-memory mode")
				}
				ledgerConstruction = call.Pos()
			}
			if selector.Sel.Name == "NewServerWithOptionsContext" && !local {
				t.Error("local server constructor is reachable outside explicit local-memory mode")
			}
			if selector.Sel.Name == "NewNativeServerWithOptionsContext" {
				nativeConstructors++
				if !durable {
					t.Error("native server constructor is not guarded by the PostgreSQL profile")
				}
			}
			return true
		})
	}
	inspect(run.Body, false, false)
	if legacyCalls != 2 || durableCalls != 2 || nativeConstructors != 1 {
		t.Fatalf("startup bindings: local-bootstrap=%d durable-bootstrap=%d native-constructor=%d", legacyCalls, durableCalls, nativeConstructors)
	}
	if ledgerConstruction != 0 && (durableBootstrap == 0 || durableBootstrap > ledgerConstruction) {
		t.Error("durable bootstrap depends on prior Ledger construction")
	}
}
