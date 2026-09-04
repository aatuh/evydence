package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestBindLedgerReplacesEveryContextDependency(t *testing.T) {
	t.Parallel()

	first := app.NewLedger(app.Config{APIKeyPepper: "first-test-pepper"})
	second := app.NewLedger(app.Config{APIKeyPepper: "second-test-pepper"})
	server, err := NewServer(first)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	assertServerContextDependencies(t, server, first)
	server.bindLedger(second)
	assertServerContextDependencies(t, server, second)
}

func assertServerContextDependencies(t *testing.T, server *Server, ledger *app.Ledger) {
	t.Helper()
	if server.ledger != ledger {
		t.Fatal("compatibility ledger was not rebound")
	}
	if server.authn != ledger {
		t.Fatal("authenticator was not rebound")
	}
	executor, ok := server.idempotency.(ledgerIdempotencyExecutor)
	if !ok || executor.ledger != ledger {
		t.Fatal("idempotency executor was not rebound")
	}
	if server.identityAccess != ledger {
		t.Fatal("identity access service was not rebound")
	}
	if server.releaseCatalog != ledger {
		t.Fatal("release catalog service was not rebound")
	}
	if server.evidenceIngestion != ledger {
		t.Fatal("evidence ingestion service was not rebound")
	}
}

func TestIdempotencyCommandWrappersUseOpaqueContextRebinding(t *testing.T) {
	t.Parallel()

	targets := map[string]string{
		"router.go":             "createWithLimit",
		"ingestion_handlers.go": "createStreamedEvidence",
	}
	fset := token.NewFileSet()
	for filename, functionName := range targets {
		file, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		foundFunction := false
		bindCalls := 0
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != functionName || function.Body == nil {
				continue
			}
			foundFunction = true
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.CallExpr:
					selector, ok := value.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					receiver, receiverOK := selector.X.(*ast.Ident)
					if receiverOK && receiver.Name == "scope" && selector.Sel.Name == "bind" && len(value.Args) == 1 {
						bindCalls++
					}
					if receiverOK && receiver.Name == "commandServer" && selector.Sel.Name == "bindLedger" {
						t.Errorf("%s reaches the Ledger compatibility binder", functionName)
					}
				case *ast.SelectorExpr:
					receiver, receiverOK := value.X.(*ast.Ident)
					if receiverOK && receiver.Name == "s" && value.Sel.Name == "ledger" {
						t.Errorf("%s reaches s.ledger directly", functionName)
					}
					if receiverOK && receiver.Name == "app" && value.Sel.Name == "Ledger" {
						t.Errorf("%s depends on *app.Ledger", functionName)
					}
				case *ast.AssignStmt:
					for _, expression := range value.Lhs {
						selector, ok := expression.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						receiver, receiverOK := selector.X.(*ast.Ident)
						if receiverOK && receiver.Name == "commandServer" && selector.Sel.Name == "ledger" {
							t.Errorf("%s assigns the compatibility ledger directly", functionName)
						}
					}
				}
				return true
			})
		}
		if !foundFunction {
			t.Errorf("%s was not found in %s", functionName, filename)
		} else if bindCalls != 1 {
			t.Errorf("%s opaque scope bind calls = %d, want 1", functionName, bindCalls)
		}
	}
}

func TestContextOwnedHandlersDoNotCallLedgerDirectly(t *testing.T) {
	t.Parallel()

	handlers := map[string]struct{}{}
	for _, name := range []string{
		// Identity and access.
		"authenticate", "createAPIKey", "listAPIKeys", "createOrganization", "createUser", "deactivateUser",
		"createRoleBinding", "listRoleBindings", "createSSOProvider", "updateSSOProviderTrustMaterial",
		"refreshSSOProviderOIDCTrustMaterial", "linkSSOIdentity", "createSSOSession", "exchangeSSOCredential",
		"revokeSSOSession", "logoutSSOSession",
		// Release catalog.
		"createProduct", "listProducts", "getProduct", "createProject", "getProject", "createRelease", "getRelease",
		"startReleaseEvidenceFlow", "freezeRelease", "approveRelease", "createReleaseCandidate", "listReleaseCandidates",
		"getReleaseCandidate", "promoteReleaseCandidate", "rejectReleaseCandidate", "transitionReleaseCandidate",
		"registerArtifact", "getArtifact", "registerContainerImage",
		"createBuild", "getBuild", "uploadBuildAttestation",
		// Evidence ingestion.
		"uploadSecurityScan", "uploadAPISecurityScan", "uploadManualSecurityDocument", "uploadSPDXSBOM", "createSBOMDiff",
		"createEvidence", "listEvidence", "searchEvidence", "getEvidence", "supersedeEvidence", "linkEvidence",
		"recordEvidenceLifecycleEvent", "listEvidenceLifecycleEvents", "uploadSBOM", "getSBOM", "listSBOMComponents",
		"uploadVEX", "previewVEXImport", "getVEX", "getVEXImportReport", "uploadCycloneDXVEX",
		"previewCycloneDXVEXImport", "uploadVulnerabilityScan", "getVulnerabilityScan", "uploadOpenAPIContract",
		"getOpenAPIContract", "createOpenAPIDiff",
	} {
		handlers[name] = struct{}{}
	}

	found := map[string]bool{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob Go files: %v", err)
	}
	fset := token.NewFileSet()
	for _, filename := range files {
		if filepath.Ext(filename) != ".go" || filename == "context_dependencies_test.go" {
			continue
		}
		file, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			if _, ok := handlers[function.Name.Name]; !ok {
				continue
			}
			found[function.Name.Name] = true
			ast.Inspect(function.Body, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				receiver, ok := selector.X.(*ast.Ident)
				if ok && receiver.Name == "s" && selector.Sel.Name == "ledger" {
					t.Errorf("%s references s.ledger directly", function.Name.Name)
				}
				return true
			})
		}
	}
	for handler := range handlers {
		if !found[handler] {
			t.Errorf("context-owned handler %s was not found", handler)
		}
	}
}
