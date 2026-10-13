package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/authz"
	"github.com/aatuh/evydence/internal/domain"
)

// Each registered operation must execute a native application-policy scenario,
// not just declare metadata or route a mocked permission error. Public trust
// modes reuse their dedicated real-crypto/token matrices. The paired coverage
// test fails until every real positive/negative scenario is implemented.
func TestRouteAuthorizationBehaviorMatrix(t *testing.T) {
	cases := nativeRouteAuthorizationCases()
	for _, route := range (&Server{}).routeDefinitions() {
		if run, ok := cases[route.op.OperationID]; ok {
			t.Run(route.op.OperationID, run)
		}
	}
}

// Keep completeness separate from execution so an individual implemented
// scenario can be selected during TDD. The unfiltered suite must still fail
// until every registered operation has an executable scenario.
func TestRouteAuthorizationBehaviorCoverage(t *testing.T) {
	cases := nativeRouteAuthorizationCases()
	known := make(map[string]bool)
	var missing []string
	for _, route := range (&Server{}).routeDefinitions() {
		id := route.op.OperationID
		known[id] = true
		if _, ok := cases[id]; !ok {
			missing = append(missing, id)
		}
	}
	for id := range cases {
		if !known[id] {
			t.Errorf("authorization scenario targets an unregistered operation: %s", id)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Errorf("%d/%d routes still lack executed native authorization scenarios: %s", len(missing), len(known), strings.Join(missing, ", "))
	}
}

type nativeAuthorizationFixture struct {
	server         *Server
	factory        *app.MemoryUnitOfWorkFactory
	ledger         *repositoryFixture
	owner          operationsFixtureScope
	foreign        operationsFixtureScope
	project        domain.Project
	control        controlFixtureScope
	report         packageReportFixtureScope
	evidence       evidenceReadFixtureScope
	integration    integrationFixtureScope
	membership     membershipFixtureScope
	binding        domain.RoleBinding
	artifact       domain.Artifact
	build          domain.BuildRun
	candidate      domain.ReleaseCandidate
	environment    domain.DeploymentEnvironment
	deployment     domain.DeploymentEvent
	waiver         domain.Waiver
	exception      domain.Exception
	questionnaire  questionnaireFixtureScope
	workflow       riskWorkflowFixtureScope
	peripheral     peripheralFixtureScope
	template       domain.CustomReportTemplate
	raw            []byte
	objects        *signatureFixtureStore
	signingKey     domain.SigningKey
	legalHold      domain.LegalHold
	sso            ssoProviderFixtureScope
	session        domain.SSOSession
	sessionSecret  string
	targetSBOM     domain.SBOM
	targetContract domain.OpenAPIContract
	transparency   transparencyFixtureScope
	proofFetcher   *countingTransparencyFixtureFetcher
	reportSigning  reportSigningFixtureScope
	providerSigner *reportFixtureSigner
	signature      domain.ArtifactSignature
	marketplaceID  string
	portal         portalFixtureScope
	portalAccess   domain.CustomerPortalAccess
	batch          domain.MerkleBatch
	backup         domain.BackupManifest
	retention      domain.ObjectRetentionPolicy
	attestation    domain.BuildAttestation
	externalCalls  func() int
}

func newNativeAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedOperationsFixtureScope(t, ledger, "Owner"), seedOperationsFixtureScope(t, ledger, "Foreign")
	return nativeAuthorizationFixtureFromScopes(t, ledger, factory, owner, foreign)
}

func nativeAuthorizationFixtureFromScopes(t *testing.T, ledger *repositoryFixture, factory *app.MemoryUnitOfWorkFactory, owner, foreign operationsFixtureScope) nativeAuthorizationFixture {
	t.Helper()
	project, err := releaseSetup(ledger).CreateProject(t.Context(), owner.actor, owner.product.ID, "Project")
	if err != nil {
		t.Fatal(err)
	}
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	return nativeAuthorizationFixture{server: s, factory: factory, ledger: ledger, owner: owner, foreign: foreign, project: project}
}

func (f nativeAuthorizationFixture) request(t *testing.T, operation, method, path string, actor domain.Actor, body []byte, status int) *httptest.ResponseRecorder {
	return f.requestWithHeaders(t, operation, method, path, actor, body, status, nil)
}

func (f nativeAuthorizationFixture) requestWithHeaders(t *testing.T, operation, method, path string, actor domain.Actor, body []byte, status int, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	// Authentication is an explicit synthetic principal; command/query ports
	// remain the real focused services over typed transaction repositories.
	f.server.authn = &configuredAuthenticator{actor: actor}
	r := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer matrix-principal")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "authorization-"+operation+"-"+actor.TenantID)
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	if value, explicit := headers["Authorization"]; explicit && value == "" {
		// The synthetic authenticator models a missing credential as an
		// authentication failure; it must not manufacture a valid principal.
		f.server.authn = &configuredAuthenticator{err: app.ErrUnauthorized}
	}
	_, pattern := f.server.mux.Handler(r)
	matched := false
	for _, route := range f.server.routeDefinitions() {
		if route.op.OperationID == operation && pattern == method+" "+route.path {
			matched = true
		}
	}
	if !matched {
		t.Fatal("authorization scenario did not dispatch its declared operation", operation, pattern)
	}
	w := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(w, r)
	if w.Code != status {
		t.Fatalf("%s native authorization status=%d want=%d", operation, w.Code, status)
	}
	return w
}

func nativeReadAuthorizationCase(operation string, path func(nativeAuthorizationFixture) string, contains func(nativeAuthorizationFixture) string, foreignStatus int) func(*testing.T) {
	return nativeReadAuthorizationFixtureCase(operation, newNativeAuthorizationFixture, path, contains, foreignStatus)
}

func nativeReadAuthorizationFixtureCase(operation string, fixture func(*testing.T) nativeAuthorizationFixture, path func(nativeAuthorizationFixture) string, contains func(nativeAuthorizationFixture) string, foreignStatus int) func(*testing.T) {
	return nativeReadAuthorizationFixtureMethodCase(operation, http.MethodGet, fixture, path, contains, foreignStatus)
}

func nativeReadAuthorizationFixtureMethodCase(operation, method string, fixture func(*testing.T) nativeAuthorizationFixture, path func(nativeAuthorizationFixture) string, contains func(nativeAuthorizationFixture) string, foreignStatus int) func(*testing.T) {
	return nativeReadAuthorizationFixturePayloadCase(operation, method, fixture, path, nil, contains, foreignStatus)
}

func nativeReadAuthorizationFixturePayloadCase(operation, method string, fixture func(*testing.T) nativeAuthorizationFixture, path func(nativeAuthorizationFixture) string, input func(nativeAuthorizationFixture) []byte, contains func(nativeAuthorizationFixture) string, foreignStatus int) func(*testing.T) {
	return func(t *testing.T) {
		f := fixture(t)
		f.owner.actor = nativeOperationPrincipal(t, operation, f.owner.actor)
		f.foreign.actor = nativeOperationPrincipal(t, operation, f.foreign.actor)
		before, err := f.factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		var body []byte
		if input != nil {
			body = input(f)
		}
		allowed := f.request(t, operation, method, path(f), f.owner.actor, body, 200)
		if !strings.Contains(allowed.Body.String(), contains(f)) {
			t.Fatal("authorized read did not return the owned resource", operation)
		}
		denied := f.owner.actor
		denied.Scopes, denied.ResourceGrants = nil, nil
		for _, actor := range []domain.Actor{denied, f.foreign.actor} {
			status := 403
			if actor.TenantID == f.foreign.actor.TenantID {
				status = foreignStatus
			}
			out := f.request(t, operation, method, path(f), actor, body, status)
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(out.Body.Bytes(), &envelope); err != nil {
				t.Fatal("authorization response is not a structured envelope", operation, err)
			}
			// Problem.instance may echo the caller-supplied path/ID. Inspect
			// resource data, not that known request coordinate, for disclosure.
			if status != 200 && len(envelope["data"]) != 0 || bytes.Contains(envelope["data"], []byte(contains(f))) {
				t.Fatal("denied/foreign read disclosed the owned resource", operation)
			}
		}
		after, err := f.factory.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("read authorization scenario mutated repository state", operation, err)
		}
	}
}

func nativeRouteAuthorizationCases() map[string]func(*testing.T) {
	cases := map[string]func(*testing.T){
		"listProducts":                      nativeReadAuthorizationCase("listProducts", func(nativeAuthorizationFixture) string { return "/v1/products" }, func(f nativeAuthorizationFixture) string { return f.owner.product.ID }, 200),
		"getProduct":                        nativeReadAuthorizationCase("getProduct", func(f nativeAuthorizationFixture) string { return "/v1/products/" + f.owner.product.ID }, func(f nativeAuthorizationFixture) string { return f.owner.product.ID }, 404),
		"getProject":                        nativeReadAuthorizationCase("getProject", func(f nativeAuthorizationFixture) string { return "/v1/projects/" + f.project.ID }, func(f nativeAuthorizationFixture) string { return f.project.ID }, 404),
		"getRelease":                        nativeReadAuthorizationCase("getRelease", func(f nativeAuthorizationFixture) string { return "/v1/releases/" + f.owner.release.ID }, func(f nativeAuthorizationFixture) string { return f.owner.release.ID }, 404),
		"getEvidence":                       nativeReadAuthorizationCase("getEvidence", func(f nativeAuthorizationFixture) string { return "/v1/evidence/" + f.owner.evidence.ID }, func(f nativeAuthorizationFixture) string { return f.owner.evidence.ID }, 404),
		"listEvidence":                      nativeReadAuthorizationCase("listEvidence", func(nativeAuthorizationFixture) string { return "/v1/evidence" }, func(f nativeAuthorizationFixture) string { return f.owner.evidence.ID }, 200),
		"searchEvidence":                    nativeReadAuthorizationCase("searchEvidence", func(nativeAuthorizationFixture) string { return "/v1/evidence/search" }, func(f nativeAuthorizationFixture) string { return f.owner.evidence.ID }, 200),
		"accessCustomerPortalPackage":       TestPortalTokenRouteAuthorizationMatrix,
		"downloadCustomerPortalPackage":     TestPortalTokenRouteAuthorizationMatrix,
		"customerPortalPackageView":         TestPortalTokenRouteAuthorizationMatrix,
		"downloadCustomerPortalPackageView": TestPortalTokenRouteAuthorizationMatrix,
		"customerPortalPackageViewForm":     TestPortalPublicFormExposesNoPackageAndConsumesNoToken,
		"receiveIncidentWebhook":            TestSignedIncidentWebhookRouteAuthorizationMatrix,
		"exchangeSSOCredential":             TestSSOExchangeRouteAuthorizationMatrix,
		"beginOIDCAuthentication":           TestOIDCAuthenticationRequestRouteUsesConfiguredProviderTenantAndBoundsState,
	}
	for _, tc := range []struct{ operation, path string }{
		{"craReadinessReport", "/v1/reports/cra-readiness?product_id=%s&release_id=%s"},
		{"craVulnerabilityHandlingReport", "/v1/reports/cra-vulnerability-handling?product_id=%s&release_id=%s"},
		{"securityUpdateEvidenceReport", "/v1/reports/security-update-evidence?product_id=%s&release_id=%s"},
	} {
		cases[tc.operation] = nativeReadAuthorizationCase(tc.operation, func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(tc.path, f.owner.product.ID, f.owner.release.ID)
		}, func(f nativeAuthorizationFixture) string { return f.owner.release.ID }, 404)
	}
	for _, tc := range []struct{ operation, path string }{
		{"releaseReadinessReport", "/v1/reports/release-readiness?release_id="},
		{"missingEvidenceReport", "/v1/reports/missing-evidence?release_id="},
		{"releaseSecuritySummary", "/v1/releases/"},
		{"vulnerabilityDecisionSummaryReport", "/v1/reports/vulnerability-decision-summary?release_id="},
		{"vulnerabilityPostureReport", "/v1/reports/vulnerability-posture?release_id="},
	} {
		cases[tc.operation] = nativeReadAuthorizationCase(tc.operation, func(f nativeAuthorizationFixture) string {
			path := tc.path + f.owner.release.ID
			if tc.operation == "releaseSecuritySummary" {
				path += "/security-summary"
			}
			return path
		}, func(f nativeAuthorizationFixture) string { return f.owner.release.ID }, 404)
	}
	cases["incidentReport"] = nativeReadAuthorizationCase("incidentReport", func(f nativeAuthorizationFixture) string {
		return "/v1/reports/incident-package?incident_id=" + f.owner.incident.ID
	}, func(f nativeAuthorizationFixture) string { return f.owner.incident.ID }, 404)
	for _, tc := range []struct {
		operation string
		index     int
	}{{"createIncident", 0}, {"recordIncidentTimeline", 1}, {"createRemediationTask", 2}, {"createIncidentWebhookReceiver", 3}, {"createLegalHold", 4}, {"createRetentionOverride", 5}} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := operationsFixtureRequests(f.owner)[tc.index]
			return r.path, []byte(r.body)
		}, 201, 404)
	}
	for _, tc := range []struct {
		operation, path string
		body            func(nativeAuthorizationFixture) map[string]any
	}{
		{"createProduct", "/v1/products", func(nativeAuthorizationFixture) map[string]any {
			return map[string]any{"name": "New product", "slug": "new-product"}
		}},
		{"createProject", "/v1/projects", func(f nativeAuthorizationFixture) map[string]any {
			return map[string]any{"product_id": f.owner.product.ID, "name": "New project"}
		}},
		{"createRelease", "/v1/releases", func(f nativeAuthorizationFixture) map[string]any {
			return map[string]any{"product_id": f.owner.product.ID, "version": "new"}
		}},
		{"createEvidence", "/v1/evidence", func(f nativeAuthorizationFixture) map[string]any {
			return map[string]any{"product_id": f.owner.product.ID, "release_id": f.owner.release.ID, "type": "manual", "title": "New evidence", "payload_hash": "sha256:" + strings.Repeat("a", 64)}
		}},
	} {
		foreignStatus := 404
		if tc.operation == "createProduct" {
			foreignStatus = 0
		}
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			body, err := json.Marshal(tc.body(f))
			if err != nil {
				panic(err)
			}
			return tc.path, body
		}, 201, foreignStatus)
	}
	addNativeControlsAuthorizationCases(cases)
	addNativeEvidenceReadAuthorizationCases(cases)
	addNativeMembershipIntegrationAuthorizationCases(cases)
	addNativeReleaseDeploymentAuthorizationCases(cases)
	addNativeRiskPackageAuthorizationCases(cases)
	addNativeIngestionAuthorizationCases(cases)
	addNativeSystemSigningAuthorizationCases(cases)
	addNativeSSOAuthorizationCases(cases)
	addNativeMetadataAuthorizationCases(cases)
	addNativePackageAccessAuthorizationCases(cases)
	addNativeIntegrityAuthorizationCases(cases)
	addNativeProviderAuthorizationCases(cases)
	addNativeOperatorAuthorizationCases(cases)
	return cases
}

func nativeWriteAuthorizationCase(operation string, input func(nativeAuthorizationFixture) (string, []byte), status int) func(*testing.T) {
	return nativeWriteAuthorizationFixtureCase(operation, newNativeAuthorizationFixture, input, status, 0)
}

func nativeWriteAuthorizationFixtureCase(operation string, fixture func(*testing.T) nativeAuthorizationFixture, input func(nativeAuthorizationFixture) (string, []byte), status, foreignStatus int) func(*testing.T) {
	return nativeMutationAuthorizationFixtureCase(operation, fixture, input, nativeMutationExpectation{status: status, foreignStatus: foreignStatus, auditDelta: 1})
}

type nativeMutationExpectation struct {
	privateValues               []string
	status, foreignStatus       int
	resultField                 string
	auditDelta                  int
	headers                     map[string]string
	revokedInput                func(nativeAuthorizationFixture) (string, []byte)
	method                      string
	payloadStages               int
	providerSigns, proofFetches int
	externalCalls               int
	result                      string
}

func nativeMutationAuthorizationFixtureCase(operation string, fixture func(*testing.T) nativeAuthorizationFixture, input func(nativeAuthorizationFixture) (string, []byte), expected nativeMutationExpectation) func(*testing.T) {
	return func(t *testing.T) {
		f := fixture(t)
		f.owner.actor = nativeOperationPrincipal(t, operation, f.owner.actor)
		f.foreign.actor = nativeOperationPrincipal(t, operation, f.foreign.actor)
		path, body := input(f)
		method := expected.method
		if method == "" {
			method = http.MethodPost
		}
		stages := 0
		if f.objects != nil {
			stages = f.objects.stages
		}
		signs, fetches := 0, 0
		if f.providerSigner != nil {
			signs = f.providerSigner.calls
		}
		if f.proofFetcher != nil {
			fetches = f.proofFetcher.calls
		}
		external := 0
		if f.externalCalls != nil {
			external = f.externalCalls()
		}
		before, err := f.factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		denied := f.owner.actor
		denied.Scopes, denied.ResourceGrants = nil, nil
		revoked := f.owner.actor
		revoked.KeyID, revoked.UserID, revoked.ResourceGrants = "", "revoked-human", nil
		noAuth := f.requestWithHeaders(t, operation, method, path, denied, body, 401, map[string]string{"Authorization": ""})
		if strings.Contains(noAuth.Body.String(), `"data"`) {
			t.Fatal("unauthenticated mutation exposed a result", operation)
		}
		for _, actor := range []domain.Actor{denied, revoked} {
			deniedPath, deniedBody := path, body
			if actor.UserID == revoked.UserID && expected.revokedInput != nil {
				deniedPath, deniedBody = expected.revokedInput(f)
			}
			out := f.requestWithHeaders(t, operation, method, deniedPath, actor, deniedBody, 403, expected.headers)
			if strings.Contains(out.Body.String(), `"data"`) {
				t.Fatal("denied mutation exposed a result", operation)
			}
			after, err := f.factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("denied mutation changed repository/replay/audit state", operation, err)
			}
		}
		if expected.foreignStatus != 0 {
			out := f.requestWithHeaders(t, operation, method, path, f.foreign.actor, body, expected.foreignStatus, expected.headers)
			if strings.Contains(out.Body.String(), `"data"`) {
				t.Fatal("foreign mutation exposed an owned result", operation)
			}
			after, err := f.factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("foreign mutation changed repository/replay/audit state", operation, err)
			}
		}
		if f.objects != nil && f.objects.stages != stages {
			t.Fatal("denied mutation staged object bytes", operation)
		}
		if f.providerSigner != nil && f.providerSigner.calls != signs || f.proofFetcher != nil && f.proofFetcher.calls != fetches {
			t.Fatal("denied mutation contacted an external I/O port", operation)
		}
		if f.externalCalls != nil && f.externalCalls() != external {
			t.Fatal("denied mutation invoked an external port", operation)
		}
		allowed := f.requestWithHeaders(t, operation, method, path, f.owner.actor, body, expected.status, expected.headers)
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(allowed.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		result := envelope.Data
		if expected.resultField != "" {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(result, &fields); err != nil {
				t.Fatal(err)
			}
			result = fields[expected.resultField]
		}
		var owned struct {
			ID       string `json:"id"`
			TenantID string `json:"tenant_id"`
		}
		if err := json.Unmarshal(result, &owned); err != nil || owned.ID == "" || owned.TenantID != f.owner.actor.TenantID {
			t.Fatal("allowed mutation did not commit its owned result", operation, err)
		}
		if expected.result != "" {
			var verdict struct {
				Result string `json:"result"`
			}
			if err := json.Unmarshal(result, &verdict); err != nil || verdict.Result != expected.result {
				t.Fatal("authorized verification did not produce its expected assurance result", operation, err)
			}
		}
		after, err := f.factory.Snapshot()
		if err != nil || len(after.AuditEntries[f.owner.actor.TenantID]) != len(before.AuditEntries[f.owner.actor.TenantID])+expected.auditDelta {
			t.Fatalf("%s audit delta=%d want=%d err=%v", operation, len(after.AuditEntries[f.owner.actor.TenantID])-len(before.AuditEntries[f.owner.actor.TenantID]), expected.auditDelta, err)
		}
		if f.objects != nil && f.objects.stages != stages+expected.payloadStages {
			t.Fatal("allowed mutation lost its exact object staging effect", operation)
		}
		if f.providerSigner != nil && f.providerSigner.calls != signs+expected.providerSigns || f.proofFetcher != nil && f.proofFetcher.calls != fetches+expected.proofFetches {
			t.Fatal("allowed mutation lost its exact external I/O effect", operation)
		}
		if f.externalCalls != nil && f.externalCalls() != external+expected.externalCalls {
			t.Fatal("allowed mutation lost its exact external call effect", operation)
		}
		for _, private := range expected.privateValues {
			if private == "" {
				t.Fatal("privacy assertion has no canary", operation)
			}
			if strings.Contains(allowed.Body.String(), private) || strings.Contains(fmt.Sprintf("%#v", after), private) {
				t.Fatal("authorized response or committed state retained a raw private input", operation)
			}
		}
		assertNativeMutationPersisted(t, operation, after, owned.ID, result)
	}
}

// Positive requests use the documented primary capability, not a wildcard
// administrator. An accidental call to a different scope must break the case.
func nativeOperationPrincipal(t *testing.T, operation string, actor domain.Actor) domain.Actor {
	t.Helper()
	policy, ok := authorizationPolicyForOperation(operation)
	if !ok || len(policy.Actions) == 0 {
		t.Fatal("native principal scenario lacks an action", operation)
	}
	definition, ok := authz.DefinitionFor(policy.Actions[0])
	if !ok || definition.Scope == "" {
		t.Fatal("native principal scenario lacks a capability", operation)
	}
	actor.Scopes = []string{definition.Scope}
	return actor
}

// The response must identify the exact durable row for its own operation,
// not merely a plausible ID plus an unrelated audit event.
func assertNativeMutationPersisted(t *testing.T, operation string, snapshot app.MemoryUnitOfWorkSnapshot, id string, result json.RawMessage) {
	t.Helper()
	fields := map[string]string{
		"verifyCosignSignature": "CosignVerifications", "verifyProviderIdentity": "ProviderVerifications",
		"createMerkleBatch": "MerkleBatches", "createTransparencyCheckpoint": "TransparencyCheckpoints", "generateBackupManifest": "BackupManifests", "createObjectRetentionPolicy": "ObjectRetentionPolicies", "verifyObjectRetentionPolicy": "ObjectRetentionPolicies", "verifyAuditChain": "VerificationResults", "verifyBackupManifest": "VerificationResults", "verifyMerkleBatch": "VerificationResults", "verifyReleaseBundle": "VerificationResults", "verify": "VerificationResults", "verifyBuildAttestationSignature": "VerificationResults",
		"createProduct": "Products", "createProject": "Projects", "createRelease": "Releases", "createEvidence": "Evidence",
		"createIncident": "Incidents", "recordIncidentTimeline": "IncidentTimelineEvents", "createRemediationTask": "RemediationTasks", "createIncidentWebhookReceiver": "IncidentWebhookReceivers", "createLegalHold": "LegalHolds", "createRetentionOverride": "RetentionOverrides",
		"createControlFramework": "ControlFrameworks", "createSecurityControl": "SecurityControls", "installControlFrameworkTemplatePack": "ControlFrameworks", "linkControlEvidence": "ControlEvidence",
		"createOrganization": "Organizations", "createUser": "Users", "deactivateUser": "Users", "createRoleBinding": "RoleBindings", "createAPIKey": "APIKeys",
		"createCollector": "Collectors", "recordCollectorRelease": "CollectorReleases", "createCommercialCollector": "CommercialCollectors", "createSourceRepository": "SourceRepositories", "recordSourceCommit": "SourceCommits", "upsertSourceBranch": "SourceBranches", "recordPullRequest": "PullRequests", "uploadGitHubSourceSnapshot": "SourceRepositories", "uploadGitLabSourceSnapshot": "SourceRepositories",
		"registerArtifact": "Artifacts", "registerContainerImage": "ContainerImages", "createBuild": "BuildRuns", "createReleaseCandidate": "ReleaseCandidates", "freezeRelease": "Releases", "approveRelease": "Releases", "promoteReleaseCandidate": "ReleaseCandidates", "rejectReleaseCandidate": "ReleaseCandidates", "createDeploymentEnvironment": "DeploymentEnvironments", "recordDeployment": "DeploymentEvents",
		"createWaiver": "Waivers", "approveWaiver": "Waivers", "createException": "Exceptions", "approveException": "Exceptions", "createApproval": "Approvals", "createCustomPolicy": "CustomPolicies", "evaluateCustomPolicy": "CustomPolicyEvaluations", "recordVulnerabilityWorkflow": "VulnerabilityWorkflow", "createVulnerabilityDecision": "Decisions", "evaluatePolicy": "PolicyEvaluations",
		"createQuestionnaireTemplate": "QuestionnaireTemplates", "createQuestionnaireAnswerLibraryEntry": "AnswerLibrary", "createQuestionnairePackage": "QuestionnairePackages", "createQuestionnaireDraft": "QuestionnaireDrafts", "createEvidenceSummary": "EvidenceSummaries", "createReportTemplate": "ReportTemplates", "renderReportTemplate": "RenderedReports", "createRedactionProfile": "RedactionProfiles", "createCustomerPackage": "CustomerPackages", "createReleaseBundle": "ReleaseBundles", "exportEvidenceBundle": "EvidenceBundles", "createGraphSnapshot": "EvidenceGraphSnapshots", "createMarketplaceCollector": "MarketplaceCollectors",
		"linkEvidence": "Evidence", "supersedeEvidence": "Evidence", "recordEvidenceLifecycleEvent": "EvidenceLifecycle", "uploadSBOM": "SBOMs", "uploadSPDXSBOM": "SBOMs", "uploadVEX": "VEXDocuments", "uploadCycloneDXVEX": "VEXDocuments", "uploadVulnerabilityScan": "VulnerabilityScans", "uploadOpenAPIContract": "OpenAPIContracts", "uploadSecurityScan": "SecurityScans", "uploadAPISecurityScan": "SecurityScans", "uploadManualSecurityDocument": "ManualSecurityDocuments", "uploadBuildAttestation": "BuildAttestations",
		"rotateSigningKey": "SigningKeys", "revokeSigningKey": "SigningKeys", "createSigningProvider": "SigningProviders", "createDSSETrustRoot": "DSSETrustRoots",
		"createSSOProvider": "SSOProviders", "updateSSOProviderTrustMaterial": "SSOProviders", "refreshSSOProviderOIDCTrustMaterial": "SSOProviders", "linkSSOIdentity": "IdentityLinks", "createSSOSession": "SSOSessions", "revokeSSOSession": "SSOSessions",
		"createSBOMDiff": "SBOMDiffs", "createOpenAPIDiff": "ContractDiffs", "createPublicTransparencyLog": "PublicTransparencyLogs", "publishPublicTransparencyLogEntry": "PublicTransparencyEntries", "verifyPublicTransparencyLogEntry": "PublicTransparencyEntries", "fetchPublicTransparencyLogEntryProof": "PublicTransparencyEntries", "createPDFReportPackage": "PDFReports", "generateAnomalyReport": "AnomalyReports", "createSigningOperation": "SigningOperations", "createArtifactSignature": "ArtifactSignatures",
		"craReadinessHTMLPackage": "HTMLReports", "createCustomerPortalAccess": "CustomerPortalAccess", "revokeCustomerPortalAccess": "CustomerPortalAccess", "importEvidenceBundle": "BundleImports", "createSaaSEditionProfile": "SaaSEditionProfiles",
	}
	field := reflect.ValueOf(snapshot).FieldByName(fields[operation])
	if !field.IsValid() || field.Kind() != reflect.Map {
		t.Fatal("mutation scenario lacks an explicit repository assertion", operation)
	}
	row := field.MapIndex(reflect.ValueOf(id))
	if !row.IsValid() {
		t.Fatal("authorized response has no committed row in its repository", operation)
	}
	stored, err := json.Marshal(row.Interface())
	if err != nil {
		t.Fatal(err)
	}
	var actual, want any
	if err := json.Unmarshal(result, &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stored, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatal("authorized response differs from its committed row", operation)
	}
}
