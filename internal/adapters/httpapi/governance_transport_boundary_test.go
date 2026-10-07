package httpapi

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestGovernanceTransportRequiresFocusedCommands(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ handler, delegate string }{
		{"createWaiver", "createDurableWaiver"}, {"approveWaiver", "approveDurableWaiver"},
		{"createException", "createDurableException"}, {"approveException", "approveDurableException"},
		{"createApproval", "createDurableApproval"},
	} {
		t.Run(tc.handler, func(t *testing.T) {
			found, delegated := false, 0
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != tc.handler {
					continue
				}
				found = true
				ast.Inspect(function.Body, func(node ast.Node) bool {
					selector, ok := node.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					owner, ok := selector.X.(*ast.Ident)
					if !ok || owner.Name != "s" {
						return true
					}
					switch selector.Sel.Name {
					case "ledger", "riskDecisions", "create", "createWithActor", "createWithActorFingerprint", "waiverCommands", "exceptionCommands", "approvalCommands":
						t.Errorf("%s retains a broad or optional governance branch %s", tc.handler, selector.Sel.Name)
					case tc.delegate:
						delegated++
					}
					return true
				})
			}
			if !found || delegated != 1 {
				t.Errorf("%s found=%t delegates=%d, want true/1", tc.handler, found, delegated)
			}
		})
	}
	dependencies, err := parser.ParseFile(token.NewFileSet(), "context_dependencies.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(dependencies, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "riskDecisionService" {
			return true
		}
		iface := spec.Type.(*ast.InterfaceType)
		for _, field := range iface.Methods.List {
			for _, name := range field.Names {
				switch name.Name {
				case "CreateWaiver", "ApproveWaiver", "CreateException", "ApproveException", "CreateApprovalRecord":
					t.Errorf("broad Risk interface retains retired governance method %s", name.Name)
				}
			}
		}
		return false
	})
}

func TestGovernanceHTTPFixtureExplicitlySuppliesFocusedGovernanceRepositories(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(_ context.Context, repos app.Repositories) error {
		if _, ok := repos.Governance.(riskapp.WaiverCommandReader); !ok {
			t.Fatal("fixture lacks focused waiver reader")
		}
		if _, ok := repos.Governance.(riskapp.ApprovalReader); !ok {
			t.Fatal("fixture lacks focused approval reader")
		}
		if _, ok := repos.Decisions.(riskapp.ExceptionCommandReader); !ok {
			t.Fatal("fixture lacks focused exception reader")
		}
		return nil
	}); err != nil {
		t.Fatal("HTTP fixture lacks an explicit unit of work", err)
	}
}
