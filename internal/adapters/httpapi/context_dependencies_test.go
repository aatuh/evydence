package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestBindLedgerReplacesEveryContextDependency(t *testing.T) {
	t.Parallel()

	first := newLegacyLedgerFixture(app.Config{APIKeyPepper: "first-test-pepper"})
	second := newLegacyLedgerFixture(app.Config{APIKeyPepper: "second-test-pepper"})
	server, err := newLegacyServerFixture(first)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	assertServerContextDependencies(t, server, first)
	server.bindLegacyLedgerFixture(second)
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
	executor, ok := server.idempotency.(legacyFixtureIdempotencyExecutor)
	if !ok || executor.ledger != ledger {
		t.Fatal("idempotency executor was not rebound")
	}
	if server.identityAccess != ledger {
		t.Fatal("identity access service was not rebound")
	}
	if reflect.ValueOf(server).Elem().FieldByName("releaseCatalog").IsValid() {
		t.Fatal("broad release catalog binding was not deleted")
	}
	if reflect.ValueOf(server).Elem().FieldByName("localDeployments").IsValid() {
		t.Fatal("broad deployment binding was not deleted")
	}
	for _, name := range []string{"localEvidenceCreation", "localEvidenceRelationships"} {
		if reflect.ValueOf(server).Elem().FieldByName(name).IsValid() {
			t.Fatalf("broad evidence binding %s was not deleted", name)
		}
	}
	for _, name := range []string{"localReportTemplates", "localBundleImport", "localEvidenceBundles"} {
		if reflect.ValueOf(server).Elem().FieldByName(name).IsValid() {
			t.Fatalf("broad package binding %s was not deleted", name)
		}
	}
	if server.evidenceIngestion != ledger {
		t.Fatal("evidence ingestion service was not rebound")
	}
	for name, dependency := range map[string]any{
		"evidence": server.evidencePointQuery, "sbom": server.sbomPointQuery,
		"scan": server.vulnerabilityScanPointQuery, "contract": server.openAPIContractPointQuery,
		"vex": server.vexPointQuery, "vex-preview": server.vexPreviewQuery,
	} {
		reader, ok := dependency.(evidenceReadFixture)
		if !ok || reader.ledger != ledger {
			t.Fatalf("focused %s fixture reader was not rebound", name)
		}
	}
	if reader, ok := server.evidencePageQuery.(evidencePageFixture); !ok || reader.ledger != ledger {
		t.Fatal("focused evidence page fixture reader was not rebound")
	}
	if reader, ok := server.lifecycleEventsQuery.(lifecyclePageFixture); !ok || reader.ledger != ledger {
		t.Fatal("focused lifecycle page fixture reader was not rebound")
	}
	if reader, ok := server.sbomComponentsQuery.(sbomComponentsFixture); !ok || reader.ledger != ledger {
		t.Fatal("focused SBOM page fixture reader was not rebound")
	}
	if reflect.ValueOf(server).Elem().FieldByName("riskDecisions").IsValid() {
		t.Fatal("broad Risk service binding was not deleted")
	}
	for name, dependency := range map[string]any{
		"vulnerability-decision": server.vulnerabilityDecisionCommands, "policy-evaluation": server.policyEvaluationCommands,
	} {
		commands, ok := dependency.(riskCommandFixture)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture command was not rebound", name)
		}
	}
	if reflect.ValueOf(server).Elem().FieldByName("packages").IsValid() {
		t.Fatal("broad Package service binding was not deleted")
	}
	if reflect.ValueOf(server).Elem().FieldByName("verification").IsValid() {
		t.Fatal("broad Verification service binding was not deleted")
	}
	for name, dependency := range map[string]any{
		"product": server.productCommands, "project": server.projectCommands, "release": server.releaseCreationCommands,
	} {
		commands, ok := dependency.(catalogFixtureCommands)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture port was not rebound", name)
		}
	}
	for name, dependency := range map[string]any{
		"artifact": server.artifactCommands, "image": server.containerImageCommands, "build": server.buildCommands, "candidate": server.candidateCommands,
	} {
		commands, ok := dependency.(registrationFixtureCommands)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture port was not rebound", name)
		}
	}
	durable, ok := server.durableCommandExecutor.(catalogFixtureReplayExecutor)
	if !ok || durable.ledger != ledger {
		t.Fatal("focused fixture replay was not rebound")
	}
	for name, dependency := range map[string]any{
		"release-state": server.releaseStateCommands, "candidate-state": server.candidateStateCommands, "attestation": server.buildAttestationCommands,
	} {
		commands, ok := dependency.(lifecycleFixtureCommands)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture port was not rebound", name)
		}
	}
	for name, dependency := range map[string]any{
		"products": server.productQuery, "catalog-points": server.catalogPointQuery, "flow": server.evidenceFlowQuery,
		"artifacts": server.artifactPointQuery, "builds": server.buildPointQuery, "candidates": server.releaseCandidateQuery,
	} {
		query, ok := dependency.(catalogQueryFixture)
		if !ok || query.ledger != ledger {
			t.Fatalf("focused %s fixture query was not rebound", name)
		}
	}
	keys, ok := server.apiKeyQuery.(apiKeyFixtureQuery)
	if !ok || keys.ledger != ledger {
		t.Fatal("focused API-key fixture query was not rebound")
	}
	bindings, ok := server.roleBindingQuery.(roleBindingFixtureQuery)
	if !ok || bindings.ledger != ledger {
		t.Fatal("focused role-binding fixture query was not rebound")
	}
	keyCommands, ok := server.apiKeyCommands.(apiKeyFixtureCommands)
	if !ok || keyCommands.ledger != ledger {
		t.Fatal("focused API-key fixture command was not rebound")
	}
	for name, dependency := range map[string]any{
		"environment": server.deploymentEnvironmentCommands, "deployment": server.deploymentCommands,
	} {
		commands, ok := dependency.(deploymentFixtureCommands)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture command was not rebound", name)
		}
	}
	for name, dependency := range map[string]any{
		"deployment-list": server.deploymentListQuery, "deployment-point": server.deploymentPointQuery,
	} {
		query, ok := dependency.(deploymentQueryFixture)
		if !ok || query.ledger != ledger {
			t.Fatalf("focused %s fixture query was not rebound", name)
		}
	}
	for name, dependency := range map[string]any{
		"evidence-creation": server.evidenceCreationCommands, "evidence-relationships": server.evidenceRelationshipCommands,
	} {
		commands, ok := dependency.(evidenceFixtureCommands)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture command was not rebound", name)
		}
	}
	for name, dependency := range map[string]any{
		"report-template": server.reportTemplateCommands, "bundle-import": server.bundleImportCommand, "bundle-export": server.evidenceBundleCommands,
		"release-bundle": server.releaseBundleCommands, "customer-package": server.customerPackageCreationCommands, "redaction": server.redactionProfileCommands,
		"customer-access": server.customerPackageAccessCommands, "html-report": server.htmlReportCommands,
	} {
		commands, ok := dependency.(packageFixtureCommands)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture command was not rebound", name)
		}
	}
	readiness, ok := server.releaseReadinessReportQuery.(packageReadinessFixtureQuery)
	if !ok || readiness.ledger != ledger {
		t.Fatal("focused readiness fixture query was not rebound")
	}
	for name, dependency := range map[string]any{
		"audit-chain": server.auditChainVerification, "merkle": server.merkleVerification, "backup": server.backupVerification,
	} {
		commands, ok := dependency.(verificationReadFixtureCommands)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture verifier was not rebound", name)
		}
	}
	keyReader, ok := server.signingKeyQuery.(signingKeyFixtureQuery)
	if !ok || keyReader.ledger != ledger {
		t.Fatal("focused signing-key fixture reader was not rebound")
	}
	auditReader, ok := server.auditLogQuery.(auditLogFixtureQuery)
	if !ok || auditReader.ledger != ledger {
		t.Fatal("focused audit-log fixture reader was not rebound")
	}
	custodyReader, ok := server.signingCustodyQuery.(custodyFixtureQuery)
	if !ok || custodyReader.ledger != ledger {
		t.Fatal("focused custody fixture reader was not rebound")
	}
	for name, dependency := range map[string]any{
		"signing-key": server.signingKeyCommands, "trust-configuration": server.trustConfigurationCommands,
	} {
		commands, ok := dependency.(signingAdministrationFixtureCommands)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture command was not rebound", name)
		}
	}
	for name, dependency := range map[string]any{
		"subject": server.subjectVerification, "release-bundle-verification": server.releaseBundleVerification,
		"DSSE": server.dsseVerification, "Cosign": server.cosignVerification,
		"backup-generation": server.backupGenerationCommands, "merkle-creation": server.merkleCreationCommands,
		"checkpoint-creation": server.transparencyCheckpointCommands, "object-retention": server.retentionCommands,
	} {
		commands, ok := dependency.(verificationCommandFixture)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture command was not rebound", name)
		}
	}
	decisions, ok := server.vulnerabilityDecisionQuery.(decisionQueryFixture)
	if !ok || decisions.ledger != ledger {
		t.Fatal("focused decision fixture query was not rebound")
	}
	exceptions, ok := server.exceptionsQuery.(exceptionQueryFixture)
	if !ok || exceptions.ledger != ledger {
		t.Fatal("focused exception fixture query was not rebound")
	}
	summary, ok := server.vulnerabilityDecisionSummaryQuery.(decisionSummaryQueryFixture)
	if !ok || summary.ledger != ledger {
		t.Fatal("focused decision summary fixture query was not rebound")
	}
	for name, dependency := range map[string]any{
		"waiver": server.waiverCommands, "exception": server.exceptionCommands, "approval": server.approvalCommands,
	} {
		commands, ok := dependency.(governanceFixtureCommands)
		if !ok || commands.ledger != ledger {
			t.Fatalf("focused %s fixture command was not rebound", name)
		}
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
					if receiverOK && receiver.Name == "commandServer" && selector.Sel.Name == "bindLegacyLedgerFixture" {
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
				if ok && (selector.Sel.Name == "WithBody" || selector.Sel.Name == "ledger" || selector.Sel.Name == "bindLegacyLedgerFixture") {
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
				if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "ledger" || selector.Sel.Name == "releaseCatalog" || selector.Sel.Name == "bindLegacyLedgerFixture" || selector.Sel.Name == "createConditional" || selector.Sel.Name == "createWithActorFingerprint") {
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
		if !found || native != 1 || fingerprints != 1 {
			t.Errorf("%s found=%t native=%d fingerprints=%d; want one native path and its revision fingerprint", name, found, native, fingerprints)
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
