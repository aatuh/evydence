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

	first := newLegacyLedgerFixture(app.Config{APIKeyPepper: "first-test-pepper"})
	second := newLegacyLedgerFixture(app.Config{APIKeyPepper: "second-test-pepper"})
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
	if server.localDeployments != ledger {
		t.Fatal("local deployment dependency was not rebound")
	}
	if server.localEvidenceCreation != ledger {
		t.Fatal("local evidence creation dependency was not rebound")
	}
	if server.localReportTemplates != ledger {
		t.Fatal("local report template dependency was not rebound")
	}
	if server.localBundleImport != ledger {
		t.Fatal("local bundle import dependency was not rebound")
	}
	if server.localEvidenceBundles != ledger {
		t.Fatal("local export dependency was not rebound")
	}
	if server.evidenceIngestion != ledger {
		t.Fatal("evidence ingestion service was not rebound")
	}
	if server.riskDecisions != ledger {
		t.Fatal("risk decision service was not rebound")
	}
	if server.packages != ledger {
		t.Fatal("package service was not rebound")
	}
	if server.verification != ledger {
		t.Fatal("verification service was not rebound")
	}
}

func TestIdempotencyCommandWrappersUseOpaqueContextRebinding(t *testing.T) {
	t.Parallel()

	targets := map[string]string{
		"router.go":             "createWithActorFingerprintAndResponseGuard",
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

func TestCreateWrappersDelegateToTheOpaqueFingerprintExecutor(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ filename, function, target, fingerprint string }{
		{"router.go", "create", "createWithLimit", ""},
		{"router.go", "createWithLimit", "createWithFingerprint", "nil"},
		{"router.go", "createWithFingerprint", "createWithActorFingerprint", "actorFingerprint"},
		{"router.go", "createWithActorFingerprint", "createWithActorFingerprintAndResponseGuard", "fingerprint"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), tc.filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found, calls := false, 0
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Name.Name != tc.function || fn.Body == nil {
				continue
			}
			found = true
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if ok && (selector.Sel.Name == "WithBody" || selector.Sel.Name == "ledger" || selector.Sel.Name == "bindLedger") {
					t.Errorf("%s bypasses the opaque executor", tc.function)
				}
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok = call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != tc.target {
					return true
				}
				receiver, ok := selector.X.(*ast.Ident)
				if !ok || receiver.Name != "s" {
					return true
				}
				calls++
				if tc.fingerprint != "" {
					wantArgs := 5
					if tc.target == "createWithActorFingerprintAndResponseGuard" {
						wantArgs = 6
					}
					if len(call.Args) != wantArgs {
						t.Errorf("%s executor argument count changed", tc.function)
						return true
					}
					arg, ok := call.Args[4].(*ast.Ident)
					if !ok || arg.Name != tc.fingerprint {
						t.Errorf("%s fingerprint selection changed", tc.function)
					}
					if wantArgs == 6 {
						if last, ok := call.Args[5].(*ast.Ident); !ok || last.Name != "nil" {
							t.Errorf("%s unexpectedly enabled response authorization", tc.function)
						}
					}
				}
				return true
			})
		}
		if !found || calls != 1 {
			t.Errorf("%s delegation found=%t calls=%d, want true and one", tc.function, found, calls)
		}
	}
}

func TestConditionalTransitionsRetireLedgerWrapperAndUseNativeFingerprintExecutor(t *testing.T) {
	t.Parallel()
	old, err := parser.ParseFile(token.NewFileSet(), "conditional_idempotency.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range old.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "createConditional" {
			t.Fatal("retired Ledger conditional wrapper returned")
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "state_transitions.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"transitionRelease", "transitionReleaseCandidate"} {
		found, native, fingerprints := false, 0, 0
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != name || fn.Body == nil {
				continue
			}
			found = true
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "ledger" || selector.Sel.Name == "bindLedger" || selector.Sel.Name == "createConditional") {
					t.Errorf("%s reaches retired aggregate conditional path", name)
				}
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "createDurableWithFingerprint" {
					native++
				}
				if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "conditionalActionFingerprint" {
					fingerprints++
				}
				return true
			})
		}
		if !found || native != 1 || fingerprints != 2 {
			t.Errorf("%s found=%t native=%d fingerprints=%d; want one native and both profile fingerprints", name, found, native, fingerprints)
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
		// Risk decisions and governance.
		"createWaiver", "approveWaiver", "createApproval", "createVulnerabilityDecision",
		"listVulnerabilityDecisions", "vulnerabilityDecisionSummaryReport", "evaluatePolicy",
		"createException", "listExceptions", "approveException",
		// Package generation and read-only readiness reporting.
		"createReleaseBundle", "createRedactionProfile", "createCustomerPackage", "getCustomerPackage", "exportEvidenceBundle",
		"importEvidenceBundle", "createReportTemplate", "renderReportTemplate", "craReadinessHTMLPackage", "releaseReadinessReport",
		"createDurableQuestionnaireDraft",
		"createDurableGraphSnapshot",
		"createDurablePDFReportPackage",
		"generateDurableAnomalyReport",
		"createDurableSaaSProfile",
		"createDurableMarketplaceCollector",
		"createDurablePublicTransparencyLog", "publishDurablePublicTransparencyLogEntry",
		"verifyDurablePublicTransparencyLogEntry",
		"fetchDurablePublicTransparencyLogEntryProof",
		"createDurableQuestionnairePackage",
		"createDurablePortalAccess", "revokeDurablePortalAccess",
		"createDurableQuestionnaireTemplate",
		"createDurableAnswerLibraryEntry",
		// Verification policy and signing-key administration.
		"verifyReleaseBundle", "verifyAuditChain", "verifyCosignSignature", "verifyBuildAttestationSignature", "createDSSETrustRoot",
		"createMerkleBatch", "verifyMerkleBatch", "createTransparencyCheckpoint", "createObjectRetentionPolicy",
		"verifyObjectRetentionPolicy", "signingCustodyReviewReport", "generateBackupManifest", "verifyBackupManifest",
		"listSigningKeys", "rotateSigningKey", "revokeSigningKey", "createSigningProvider", "verifySubject",
		"createDurableSigningOperation",
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
