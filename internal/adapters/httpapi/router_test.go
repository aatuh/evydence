package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

func TestRoutesValidateAndOpenAPIRenders(t *testing.T) {
	ledger := app.NewLedger(app.Config{APIKeyPepper: "test"})
	server, err := NewServer(ledger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := server.ValidateRoutes(); err != nil {
		t.Fatalf("ValidateRoutes: %v", err)
	}
	doc, err := server.OpenAPI()
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if !bytes.Contains(doc, []byte(`"openapi"`)) || !bytes.Contains(doc, []byte(`BearerAuth`)) {
		t.Fatalf("OpenAPI document missing expected fields: %s", doc)
	}
}

func TestRouteFamiliesRegisterCriticalPaths(t *testing.T) {
	server, _ := testServer(t)
	groups := map[string][]routeDef{
		"system":   server.systemRoutes(),
		"identity": server.identityRoutes(),
		"portal":   server.packagePortalRoutes(),
		"ops":      server.integrityOpsRoutes(),
	}
	for name, routes := range groups {
		if len(routes) == 0 {
			t.Fatalf("%s route group is empty", name)
		}
	}
	want := map[string]string{
		"instanceAdminSnapshot":         "/v1/admin/instance",
		"createSSOSession":              "/v1/sso/sessions",
		"createCustomerPortalAccess":    "/v1/customer-portal/access",
		"accessCustomerPortalPackage":   "/v1/customer-portal/package",
		"downloadCustomerPackage":       "/v1/customer-packages/{id}/download",
		"downloadCustomerPortalPackage": "/v1/customer-portal/package/download",
		"receiveIncidentWebhook":        "/v1/incident-webhooks/{receiver_id}",
		"createLegalHold":               "/v1/legal-holds",
		"verifyReleaseBundle":           "/v1/release-bundles/{id}/verify",
	}
	got := map[string]string{}
	for _, route := range server.routeDefinitions() {
		got[route.op.OperationID] = route.path
	}
	for opID, path := range want {
		if got[opID] != path {
			t.Fatalf("operation %s path = %q, want %q", opID, got[opID], path)
		}
	}
}

func TestOpenAPICriticalRoutesHavePreciseContracts(t *testing.T) {
	server, _ := testServer(t)
	docBytes, err := server.OpenAPI()
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	schemas := asStringAnyMap(t, asStringAnyMap(t, doc["components"])["schemas"])
	problem := asStringAnyMap(t, schemas["Problem"])
	problemProps := asStringAnyMap(t, problem["properties"])
	if _, ok := problemProps["request_id"]; !ok {
		t.Fatalf("Problem schema missing request_id: %#v", problemProps)
	}
	for _, schemaName := range []string{"ReadinessStatusEnvelope", "BackupManifestEnvelope", "VerificationResultEnvelope", "ReadinessReportEnvelope", "CreateProductRequest", "ProductEnvelope", "ProductListEnvelope", "CreateProjectRequest", "ProjectEnvelope", "CreateReleaseRequest", "ReleaseEnvelope", "RegisterArtifactRequest", "ArtifactEnvelope", "CreateBuildRequest", "BuildRunEnvelope", "EvidenceUploadRequest", "SBOMEnvelope", "VEXDocumentEnvelope", "UploadVulnerabilityScanRequest", "VulnerabilityScanEnvelope", "CreateEvidenceRequest", "CreateReleaseBundleRequest", "CreateSSOProviderRequest", "SSOProviderEnvelope", "VerifyProviderIdentityRequest", "ProviderVerificationEnvelope", "CreateSSOSessionRequest", "SSOSessionCreateEnvelope", "CreateCustomerPortalAccessRequest", "CustomerPortalAccessCreateEnvelope", "CustomerPortalPackageRequest", "DataEnvelope"} {
		if _, ok := schemas[schemaName]; !ok {
			t.Fatalf("schema %s missing from OpenAPI components", schemaName)
		}
	}

	paths := asStringAnyMap(t, doc["paths"])
	ready := operationMap(t, paths, "/v1/ready", "get")
	assertResponseRef(t, ready, "200", "#/components/schemas/ReadinessStatusEnvelope")
	backupManifest := operationMap(t, paths, "/v1/backup-manifests", "post")
	assertRequestRef(t, backupManifest, "#/components/schemas/EmptyObject")
	assertResponseRef(t, backupManifest, "201", "#/components/schemas/BackupManifestEnvelope")
	verifyBackup := operationMap(t, paths, "/v1/backup-manifests/{id}/verify", "get")
	assertResponseRef(t, verifyBackup, "200", "#/components/schemas/VerificationResultEnvelope")
	releaseReadiness := operationMap(t, paths, "/v1/reports/release-readiness", "get")
	assertQueryParams(t, releaseReadiness, "release_id")
	assertResponseRef(t, releaseReadiness, "200", "#/components/schemas/ReadinessReportEnvelope")
	craReadiness := operationMap(t, paths, "/v1/reports/cra-readiness", "get")
	assertQueryParams(t, craReadiness, "product_id", "release_id")
	assertResponseRef(t, craReadiness, "200", "#/components/schemas/ReadinessReportEnvelope")
	createProduct := operationMap(t, paths, "/v1/products", "post")
	assertRequestRef(t, createProduct, "#/components/schemas/CreateProductRequest")
	assertResponseRef(t, createProduct, "201", "#/components/schemas/ProductEnvelope")
	listProducts := operationMap(t, paths, "/v1/products", "get")
	assertResponseRef(t, listProducts, "200", "#/components/schemas/ProductListEnvelope")
	createProject := operationMap(t, paths, "/v1/projects", "post")
	assertRequestRef(t, createProject, "#/components/schemas/CreateProjectRequest")
	assertResponseRef(t, createProject, "201", "#/components/schemas/ProjectEnvelope")
	createRelease := operationMap(t, paths, "/v1/releases", "post")
	assertRequestRef(t, createRelease, "#/components/schemas/CreateReleaseRequest")
	assertResponseRef(t, createRelease, "201", "#/components/schemas/ReleaseEnvelope")
	getRelease := operationMap(t, paths, "/v1/releases/{id}", "get")
	assertResponseRef(t, getRelease, "200", "#/components/schemas/ReleaseEnvelope")
	freezeRelease := operationMap(t, paths, "/v1/releases/{id}/freeze", "post")
	assertRequestRef(t, freezeRelease, "#/components/schemas/EmptyObject")
	assertResponseRef(t, freezeRelease, "200", "#/components/schemas/ReleaseEnvelope")
	registerArtifact := operationMap(t, paths, "/v1/artifacts", "post")
	assertRequestRef(t, registerArtifact, "#/components/schemas/RegisterArtifactRequest")
	assertResponseRef(t, registerArtifact, "201", "#/components/schemas/ArtifactEnvelope")
	createBuild := operationMap(t, paths, "/v1/builds", "post")
	assertRequestRef(t, createBuild, "#/components/schemas/CreateBuildRequest")
	assertResponseRef(t, createBuild, "201", "#/components/schemas/BuildRunEnvelope")
	uploadSBOM := operationMap(t, paths, "/v1/sboms", "post")
	assertRequestRef(t, uploadSBOM, "#/components/schemas/EvidenceUploadRequest")
	assertResponseRef(t, uploadSBOM, "201", "#/components/schemas/SBOMEnvelope")
	uploadVulnerabilityScan := operationMap(t, paths, "/v1/vulnerability-scans", "post")
	assertRequestRef(t, uploadVulnerabilityScan, "#/components/schemas/UploadVulnerabilityScanRequest")
	assertResponseRef(t, uploadVulnerabilityScan, "201", "#/components/schemas/VulnerabilityScanEnvelope")
	uploadVEX := operationMap(t, paths, "/v1/vex", "post")
	assertRequestRef(t, uploadVEX, "#/components/schemas/EvidenceUploadRequest")
	assertResponseRef(t, uploadVEX, "201", "#/components/schemas/VEXDocumentEnvelope")
	createEvidence := operationMap(t, paths, "/v1/evidence", "post")
	assertRequestRef(t, createEvidence, "#/components/schemas/CreateEvidenceRequest")
	assertProblemResponseRef(t, createEvidence, "400")
	searchEvidence := operationMap(t, paths, "/v1/evidence/search", "get")
	assertQueryParams(t, searchEvidence, "product_id", "project_id", "release_id", "type", "source", "tag", "cursor", "limit")
	createPortalAccess := operationMap(t, paths, "/v1/customer-portal/access", "post")
	assertRequestRef(t, createPortalAccess, "#/components/schemas/CreateCustomerPortalAccessRequest")
	assertResponseRef(t, createPortalAccess, "201", "#/components/schemas/CustomerPortalAccessCreateEnvelope")
	portalPackage := operationMap(t, paths, "/v1/customer-portal/package", "post")
	assertRequestRef(t, portalPackage, "#/components/schemas/CustomerPortalPackageRequest")
	if _, ok := portalPackage["security"]; ok {
		t.Fatalf("public portal token exchange should not advertise bearer security: %#v", portalPackage["security"])
	}
	downloadPackage := operationMap(t, paths, "/v1/customer-packages/{id}/download", "get")
	assertMediaResponseType(t, downloadPackage, "200", "application/zip")
	portalDownload := operationMap(t, paths, "/v1/customer-portal/package/download", "post")
	assertRequestRef(t, portalDownload, "#/components/schemas/CustomerPortalPackageRequest")
	assertMediaResponseType(t, portalDownload, "200", "application/zip")
	if _, ok := portalDownload["security"]; ok {
		t.Fatalf("public portal download should not advertise bearer security: %#v", portalDownload["security"])
	}
	incidentWebhook := operationMap(t, paths, "/v1/incident-webhooks/{receiver_id}", "post")
	assertQueryParams(t, incidentWebhook, "receiver_id", "X-Evydence-Webhook-Event-ID", "X-Evydence-Webhook-Timestamp", "X-Evydence-Webhook-Signature")
	if _, ok := incidentWebhook["security"]; ok {
		t.Fatalf("public incident webhook should not advertise bearer security: %#v", incidentWebhook["security"])
	}
	createSession := operationMap(t, paths, "/v1/sso/sessions", "post")
	assertRequestRef(t, createSession, "#/components/schemas/CreateSSOSessionRequest")
	assertResponseRef(t, createSession, "201", "#/components/schemas/SSOSessionCreateEnvelope")
	createProvider := operationMap(t, paths, "/v1/sso/providers", "post")
	assertRequestRef(t, createProvider, "#/components/schemas/CreateSSOProviderRequest")
	assertResponseRef(t, createProvider, "201", "#/components/schemas/SSOProviderEnvelope")
	verifyProvider := operationMap(t, paths, "/v1/provider-verifications", "post")
	assertRequestRef(t, verifyProvider, "#/components/schemas/VerifyProviderIdentityRequest")
	assertResponseRef(t, verifyProvider, "201", "#/components/schemas/ProviderVerificationEnvelope")
	verifyBundle := operationMap(t, paths, "/v1/release-bundles/{id}/verify", "get")
	assertQueryParams(t, verifyBundle, "id")
	assertResponseRef(t, verifyBundle, "200", "#/components/schemas/VerificationResultEnvelope")
	instanceAdmin := operationMap(t, paths, "/v1/admin/instance", "get")
	if !strings.Contains(asString(t, instanceAdmin["description"]), "instance:admin") {
		t.Fatalf("instance admin description should document exact scope: %#v", instanceAdmin["description"])
	}
}

func TestOpenAPIDoesNotAdvertiseImpossibleSuccessStatusCodes(t *testing.T) {
	server, _ := testServer(t)
	docBytes, err := server.OpenAPI()
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	for path, rawPath := range asStringAnyMap(t, doc["paths"]) {
		for method, rawOperation := range asStringAnyMap(t, rawPath) {
			operation := asStringAnyMap(t, rawOperation)
			responses := asStringAnyMap(t, operation["responses"])
			if method == "get" {
				if _, ok := responses["201"]; ok {
					t.Fatalf("GET %s advertises 201 response", path)
				}
			}
			if _, has200 := responses["200"]; method == "post" && has200 {
				if _, has201 := responses["201"]; has201 {
					t.Fatalf("POST %s advertises both 200 and 201 success responses", path)
				}
			}
		}
	}
}

func TestCreateProductRequiresAuthAndIdempotency(t *testing.T) {
	server, secret := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/products", strings.NewReader(`{"name":"Payments","slug":"payments"}`))
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status without auth = %d, want 401 body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/products", strings.NewReader(`{"name":"Payments","slug":"payments"}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status without idempotency = %d, want 400 body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/products", strings.NewReader(`{"name":"Payments","slug":"payments"}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Idempotency-Key", "create-product")
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status create = %d, want 201 body=%s", rec.Code, rec.Body.String())
	}
	first := rec.Body.String()

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/products", strings.NewReader(`{"name":"Payments","slug":"payments"}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Idempotency-Key", "create-product")
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status replay = %d, want 201 body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != first {
		t.Fatalf("idempotent replay changed response\nfirst=%s\nsecond=%s", first, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/products", strings.NewReader(`{"name":"Other","slug":"other"}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Idempotency-Key", "create-product")
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status conflict = %d, want 409 body=%s", rec.Code, rec.Body.String())
	}
}

func TestServerRateLimitReturnsSafeProblem(t *testing.T) {
	ledger := app.NewLedger(app.Config{APIKeyPepper: "test"})
	server, err := NewServerWithOptions(ledger, ServerOptions{RateLimitRequestsPerMinute: 2})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	handler := server.Handler()
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status=%d body=%s", i, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	req.RemoteAddr = "203.0.113.10:23456"
	req.Header.Set("Authorization", "Bearer should-not-leak")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "RATE_LIMITED") || strings.Contains(rec.Body.String(), "should-not-leak") {
		t.Fatalf("unsafe rate limit problem body: %s", rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" || rec.Header().Get(requestIDHeader) == "" {
		t.Fatalf("missing retry/request headers: %#v", rec.Header())
	}
}

func TestAuthenticatedReadRoutesRejectMissingBearerToken(t *testing.T) {
	server, _ := testServer(t)
	paths := []string{
		"/v1/admin/instance",
		"/v1/api-keys",
		"/v1/artifact-signatures/sig_missing",
		"/v1/audit-chain/verify",
		"/v1/audit-log",
		"/v1/backup-manifests/backup_missing/verify",
		"/v1/builds/build_missing",
		"/v1/collectors",
		"/v1/collectors/collector_missing/health",
		"/v1/commercial-collectors",
		"/v1/control-evidence",
		"/v1/control-framework-template-packs",
		"/v1/control-frameworks",
		"/v1/controls/control_missing",
		"/v1/customer-packages/package_missing",
		"/v1/customer-packages/package_missing/download",
		"/v1/deployments",
		"/v1/deployments/deployment_missing",
		"/v1/environments",
		"/v1/evidence",
		"/v1/evidence/search",
		"/v1/evidence/ev_missing",
		"/v1/evidence/ev_missing/lifecycle-events",
		"/v1/exceptions",
		"/v1/marketplace-collectors",
		"/v1/marketplace-collectors/collector_missing/health",
		"/v1/openapi-contracts/contract_missing",
		"/v1/products",
		"/v1/release-bundles/bundle_missing",
		"/v1/release-bundles/bundle_missing/manifest",
		"/v1/release-bundles/bundle_missing/verify",
		"/v1/release-candidates",
		"/v1/release-candidates/rc_missing",
		"/v1/releases/release_missing",
		"/v1/reports/control-coverage",
		"/v1/reports/cra-readiness",
		"/v1/reports/cra-readiness-html",
		"/v1/reports/incident-package",
		"/v1/reports/missing-evidence",
		"/v1/reports/retention",
		"/v1/reports/security-review-package",
		"/v1/reports/vulnerability-posture",
		"/v1/role-bindings",
		"/v1/sboms/sbom_missing",
		"/v1/signing-keys",
		"/v1/source/repositories",
		"/v1/vex/vex_missing",
		"/v1/vulnerability-scans/scan_missing",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("GET %s status=%d want 401 body=%s", path, rec.Code, rec.Body.String())
			}
			var problem map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
				t.Fatalf("decode problem response: %v body=%s", err, rec.Body.String())
			}
			if problem["detail"] != "unauthorized" || strings.Contains(asString(t, problem["detail"]), "missing") {
				t.Fatalf("unauthorized detail should stay generic: %#v", problem)
			}
		})
	}
}

func TestUnknownJSONFieldReturnsProblem(t *testing.T) {
	server, secret := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/products", strings.NewReader(`{"name":"Payments","slug":"payments","extra":true}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Idempotency-Key", "unknown-field")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "req-test-validation")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"VALIDATION_FAILED"`) {
		t.Fatalf("problem code missing: %s", rec.Body.String())
	}
	if rec.Header().Get("X-Request-ID") != "req-test-validation" || !strings.Contains(rec.Body.String(), `"request_id":"req-test-validation"`) {
		t.Fatalf("request id missing from problem/header: header=%q body=%s", rec.Header().Get("X-Request-ID"), rec.Body.String())
	}
}

func TestCrossTenantEvidenceReadDenied(t *testing.T) {
	ledger := app.NewLedger(app.Config{APIKeyPepper: "test"})
	_, _, secretA, err := ledger.BootstrapTenant(t.Context(), "Tenant A", "admin-a", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap A: %v", err)
	}
	_, _, secretB, err := ledger.BootstrapTenant(t.Context(), "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap B: %v", err)
	}
	server, err := NewServer(ledger)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	body := postJSON(t, server, secretA, "/v1/evidence", "evidence-a", map[string]any{
		"type": "build", "title": "Build", "payload_hash": "sha256:44575cf5b2853284ce5d55751bc9e87d165bd64d5ef12c55fa291e9d40afae86",
	}, http.StatusCreated)
	id := dataField(t, body, "id")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/evidence/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+secretB)
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross tenant status = %d, want 404 body=%s", rec.Code, rec.Body.String())
	}
}

func TestInstanceAdminHTTPRequiresExplicitScope(t *testing.T) {
	ledger := app.NewLedger(app.Config{APIKeyPepper: "test"})
	_, _, tenantSecret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "tenant-admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant: %v", err)
	}
	_, _, instanceSecret, err := ledger.BootstrapTenant(t.Context(), "Instance Tenant", "instance-admin", []string{"*", app.ScopeInstanceAdmin})
	if err != nil {
		t.Fatalf("bootstrap instance: %v", err)
	}
	server, err := NewServer(ledger)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	getJSON(t, server, tenantSecret, "/v1/admin/instance", http.StatusForbidden)
	getJSON(t, server, instanceSecret, "/v1/admin/instance", http.StatusOK)
}

func TestReleaseBundleVerifyFlow(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "prod", map[string]any{"name": "Payments", "slug": "payments"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	releaseBody := postJSON(t, server, secret, "/v1/releases", "rel", map[string]any{"product_id": productID, "version": "1.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	postJSON(t, server, secret, "/v1/evidence", "ev", map[string]any{
		"release_id": releaseID, "type": "build", "title": "Build", "payload_hash": "sha256:44575cf5b2853284ce5d55751bc9e87d165bd64d5ef12c55fa291e9d40afae86",
	}, http.StatusCreated)
	bundleBody := postJSON(t, server, secret, "/v1/release-bundles", "bundle", map[string]any{"release_id": releaseID}, http.StatusCreated)
	bundleID := dataField(t, bundleBody, "id")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/release-bundles/"+bundleID+"/verify", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"result":"passed"`) {
		t.Fatalf("verify did not pass: %s", rec.Body.String())
	}
}

func TestReleaseRiskDecisionHTTPFlow(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "risk-prod", map[string]any{"name": "Payments", "slug": "risk-payments"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	releaseBody := postJSON(t, server, secret, "/v1/releases", "risk-rel", map[string]any{"product_id": productID, "version": "2.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	artifactBody := postJSON(t, server, secret, "/v1/artifacts", "risk-artifact", map[string]any{"name": "api.tar.gz", "media_type": "application/gzip", "digest": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "size": 42}, http.StatusCreated)
	artifactID := dataField(t, artifactBody, "id")
	postJSON(t, server, secret, "/v1/sboms", "risk-sbom", map[string]any{
		"release_id":  releaseID,
		"artifact_id": artifactID,
		"payload": map[string]any{
			"bomFormat": "CycloneDX", "specVersion": "1.6",
			"components": []map[string]any{{"name": "openssl", "purl": "pkg:apk/openssl@3.1.0"}},
		},
	}, http.StatusCreated)
	scanBody := postJSON(t, server, secret, "/v1/vulnerability-scans", "risk-scan", map[string]any{
		"scanner": "grype", "target_ref": "pkg:oci/payments-api", "release_id": releaseID,
		"findings": []map[string]any{{"vulnerability": "CVE-2026-0099", "component": "pkg:apk/openssl@3.1.0", "severity": "critical", "state": "open"}},
	}, http.StatusCreated)
	findingID := firstFindingID(t, scanBody)
	postJSON(t, server, secret, "/v1/release-bundles", "risk-bundle", map[string]any{"release_id": releaseID}, http.StatusCreated)
	addHTTPBuildProvenance(t, server, secret, productID, releaseID, artifactID, "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")

	report := getJSON(t, server, secret, "/v1/reports/release-readiness?release_id="+releaseID, http.StatusOK)
	if !strings.Contains(report, `"result":"failed"`) || !strings.Contains(report, `"blocking_findings"`) {
		t.Fatalf("expected failed readiness report with blocking findings: %s", report)
	}
	decisionBody := postJSON(t, server, secret, "/v1/vulnerability-findings/"+findingID+"/decisions", "risk-decision", map[string]any{"status": "not_affected", "justification": "vulnerable code is not present"}, http.StatusCreated)
	replayed := postJSON(t, server, secret, "/v1/vulnerability-findings/"+findingID+"/decisions", "risk-decision", map[string]any{"status": "not_affected", "justification": "vulnerable code is not present"}, http.StatusCreated)
	if replayed != decisionBody {
		t.Fatalf("decision idempotency replay changed response\nfirst=%s\nsecond=%s", decisionBody, replayed)
	}
	report = getJSON(t, server, secret, "/v1/reports/release-readiness?release_id="+releaseID, http.StatusOK)
	if !strings.Contains(report, `"result":"passed"`) {
		t.Fatalf("expected passed readiness report after decision: %s", report)
	}
}

func TestIntegrityRuntimeHTTPFlow(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "int-prod", map[string]any{"name": "Payments", "slug": "int-payments"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	releaseBody := postJSON(t, server, secret, "/v1/releases", "int-rel", map[string]any{"product_id": productID, "version": "3.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	artifactDigest := "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
	artifactBody := postJSON(t, server, secret, "/v1/artifacts", "int-artifact", map[string]any{"name": "api.tar.gz", "media_type": "application/gzip", "digest": artifactDigest, "size": 3}, http.StatusCreated)
	artifactID := dataField(t, artifactBody, "id")
	postJSON(t, server, secret, "/v1/container-images", "int-image", map[string]any{"artifact_id": artifactID, "repository": "registry.example.com/payments", "tag": "3.0.0", "digest": artifactDigest}, http.StatusCreated)
	sigBody := postJSON(t, server, secret, "/v1/artifact-signatures", "int-sig", map[string]any{"artifact_id": artifactID, "algorithm": "cosign", "signature": "MEUCIQ"}, http.StatusCreated)
	sigID := dataField(t, sigBody, "id")
	cosign := postJSON(t, server, secret, "/v1/artifact-signatures/"+sigID+"/verify-cosign", "int-cosign", map[string]any{"rekor_uuid": "uuid", "rekor_log_index": "1"}, http.StatusOK)
	if !strings.Contains(cosign, `"result":"passed"`) {
		t.Fatalf("cosign response: %s", cosign)
	}
	postJSON(t, server, secret, "/v1/signing-providers", "int-provider", map[string]any{"name": "dev", "type": "local_encrypted_dev", "key_ref": "file://dev.keys", "encrypted": true}, http.StatusCreated)
	batchBody := postJSON(t, server, secret, "/v1/merkle-batches", "int-batch", map[string]any{}, http.StatusCreated)
	batchID := dataField(t, batchBody, "id")
	verifyBatch := getJSON(t, server, secret, "/v1/merkle-batches/"+batchID+"/verify", http.StatusOK)
	if !strings.Contains(verifyBatch, `"result":"passed"`) {
		t.Fatalf("batch verify: %s", verifyBatch)
	}
	postJSON(t, server, secret, "/v1/transparency-checkpoints", "int-transparency", map[string]any{"batch_id": batchID, "provider": "internal-rfc3161", "external_id": "ts-1"}, http.StatusCreated)
	retentionBody := postJSON(t, server, secret, "/v1/object-retention-policies", "int-retention", map[string]any{"name": "lock", "mode": "governance", "retention_days": 30}, http.StatusCreated)
	retentionID := dataField(t, retentionBody, "id")
	postJSON(t, server, secret, "/v1/object-retention-policies/"+retentionID+"/verify", "int-retention-verify", map[string]any{}, http.StatusOK)
	backupBody := postJSON(t, server, secret, "/v1/backup-manifests", "int-backup", map[string]any{}, http.StatusCreated)
	backupID := dataField(t, backupBody, "id")
	backupVerify := getJSON(t, server, secret, "/v1/backup-manifests/"+backupID+"/verify", http.StatusOK)
	if !strings.Contains(backupVerify, `"result":"passed"`) {
		t.Fatalf("backup verify: %s", backupVerify)
	}
	audit := getJSON(t, server, secret, "/v1/audit-log?subject_type=release&subject_id="+releaseID, http.StatusOK)
	if !strings.Contains(audit, releaseID) {
		t.Fatalf("audit log missing release: %s", audit)
	}
	metrics := getJSON(t, server, secret, "/v1/metrics", http.StatusOK)
	if !strings.Contains(metrics, `"resource_counts"`) {
		t.Fatalf("metrics response: %s", metrics)
	}
	metricsText := getRawWithAccept(t, server, secret, "/v1/metrics", "text/plain", http.StatusOK)
	if contentType := metricsText.Header().Get("Content-Type"); !strings.Contains(contentType, "text/plain") {
		t.Fatalf("metrics content type = %q", contentType)
	}
	if body := metricsText.Body.String(); !strings.Contains(body, "evydence_resource_count{resource=\"evidence\"}") || strings.Contains(body, secret) {
		t.Fatalf("unsafe or incomplete text metrics: %s", body)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/ready", nil)
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("ready status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestVEXAndExceptionHTTPValidation(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "vex-prod", map[string]any{"name": "VEX Product", "slug": "vex-product"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	releaseBody := postJSON(t, server, secret, "/v1/releases", "vex-rel", map[string]any{"product_id": productID, "version": "1.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	artifactBody := postJSON(t, server, secret, "/v1/artifacts", "vex-artifact", map[string]any{"name": "api.tar.gz", "media_type": "application/gzip", "digest": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "size": 42}, http.StatusCreated)
	artifactID := dataField(t, artifactBody, "id")
	postJSON(t, server, secret, "/v1/vulnerability-scans", "vex-scan", map[string]any{
		"scanner": "grype", "target_ref": "pkg:oci/payments-api", "release_id": releaseID,
		"findings": []map[string]any{{"vulnerability": "CVE-2026-0100", "component": "pkg:apk/openssl@3.1.0", "severity": "critical", "state": "open"}},
	}, http.StatusCreated)
	vexBody := postJSON(t, server, secret, "/v1/vex", "vex-upload", map[string]any{
		"release_id":  releaseID,
		"artifact_id": artifactID,
		"payload": map[string]any{
			"@context":  "https://openvex.dev/ns/v0.2.0",
			"@id":       "https://example.test/vex/1",
			"author":    "security@example.test",
			"timestamp": "2026-05-27T12:00:00Z",
			"version":   1,
			"statements": []map[string]any{{
				"vulnerability":    map[string]any{"name": "CVE-2026-0100"},
				"products":         []map[string]any{{"@id": "pkg:apk/openssl@3.1.0"}},
				"status":           "fixed",
				"justification":    "fixed in release candidate",
				"impact_statement": "patched before release",
				"action_statement": "ship fixed artifact",
			}},
		},
	}, http.StatusCreated)
	vexID := dataField(t, vexBody, "id")
	getJSON(t, server, secret, "/v1/vex/"+vexID, http.StatusOK)
	postJSON(t, server, secret, "/v1/vex", "vex-bad", map[string]any{"release_id": releaseID, "payload": map[string]any{"author": "a", "timestamp": "2026-05-27T12:00:00Z", "statements": []any{}, "extra": true}}, http.StatusBadRequest)

	exceptionBody := postJSON(t, server, secret, "/v1/exceptions", "exception-create", map[string]any{"release_id": releaseID, "reason": "temporary acceptance", "owner": "security", "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, http.StatusCreated)
	exceptionID := dataField(t, exceptionBody, "id")
	postJSON(t, server, secret, "/v1/exceptions/"+exceptionID+"/approve", "exception-approve", map[string]any{}, http.StatusOK)
	getJSON(t, server, secret, "/v1/exceptions?release_id="+releaseID, http.StatusOK)
}

func TestCollectorBuildAttestationHTTPFlow(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "prov-prod", map[string]any{"name": "Provenance Product", "slug": "provenance-product"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	projectBody := postJSON(t, server, secret, "/v1/projects", "prov-project", map[string]any{"product_id": productID, "name": "api"}, http.StatusCreated)
	projectID := dataField(t, projectBody, "id")
	releaseBody := postJSON(t, server, secret, "/v1/releases", "prov-rel", map[string]any{"product_id": productID, "version": "1.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	artifactDigest := "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	artifactBody := postJSON(t, server, secret, "/v1/artifacts", "prov-artifact", map[string]any{"name": "api.tar.gz", "media_type": "application/gzip", "digest": artifactDigest, "size": 42}, http.StatusCreated)
	artifactID := dataField(t, artifactBody, "id")

	collectorBody := postJSON(t, server, secret, "/v1/collectors", "prov-collector", map[string]any{"name": "gha", "type": "github_actions", "version": "1.0.0"}, http.StatusCreated)
	collectorSecret := nestedDataField(t, collectorBody, "secret")
	if collectorSecret == "" || strings.Contains(getJSON(t, server, secret, "/v1/collectors", http.StatusOK), collectorSecret) {
		t.Fatalf("collector secret missing or leaked in list response")
	}
	buildPayload := map[string]any{
		"project_id":   projectID,
		"release_id":   releaseID,
		"provider":     "github_actions",
		"commit_sha":   "0123456789abcdef0123456789abcdef01234567",
		"repository":   "aatuh/evydence",
		"workflow_ref": "aatuh/evydence/.github/workflows/release.yml@refs/heads/main",
		"run_id":       "123456",
		"run_attempt":  1,
		"status":       "passed",
		"started_at":   "2026-05-27T12:00:00Z",
		"oidc_subject": "repo:aatuh/evydence:ref:refs/heads/main",
		"outputs":      []map[string]any{{"artifact_id": artifactID, "digest": artifactDigest}},
	}
	buildBody := postJSON(t, server, collectorSecret, "/v1/builds", "prov-build", buildPayload, http.StatusCreated)
	buildID := dataField(t, buildBody, "id")
	replayed := postJSON(t, server, collectorSecret, "/v1/builds", "prov-build", buildPayload, http.StatusCreated)
	if replayed != buildBody {
		t.Fatalf("build idempotency replay changed response\nfirst=%s\nsecond=%s", buildBody, replayed)
	}
	getJSON(t, server, collectorSecret, "/v1/builds/"+buildID, http.StatusForbidden)
	getJSON(t, server, secret, "/v1/builds/"+buildID, http.StatusOK)
	attestationBody := postRaw(t, server, collectorSecret, "/v1/builds/"+buildID+"/attestations", "prov-attestation", dsseHTTP(t, artifactDigest), http.StatusCreated)
	attestationReplay := postRaw(t, server, collectorSecret, "/v1/builds/"+buildID+"/attestations", "prov-attestation", dsseHTTP(t, artifactDigest), http.StatusCreated)
	if attestationReplay != attestationBody {
		t.Fatalf("attestation idempotency replay changed response\nfirst=%s\nsecond=%s", attestationBody, attestationReplay)
	}
	postJSON(t, server, secret, "/v1/build-attestations/"+dataField(t, attestationBody, "id")+"/verify-signature", "prov-attestation-verify", map[string]any{}, http.StatusBadRequest)
	postRaw(t, server, collectorSecret, "/v1/builds/"+buildID+"/attestations", "prov-bad-attestation", []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"@@@","signatures":[{"sig":"abc"}]}`), http.StatusBadRequest)
}

func TestCollectorSupplyChainHTTPFlow(t *testing.T) {
	server, secret := testServer(t)
	collectorBody := postJSON(t, server, secret, "/v1/collectors", "supply-collector", map[string]any{"name": "import-bundle", "type": "import_bundle", "version": "0.1.0", "scopes": []string{"bundle:write", "evidence:write"}}, http.StatusCreated)
	collector, ok := dataMap(t, collectorBody)["collector"].(map[string]any)
	if !ok {
		t.Fatalf("collector missing: %s", collectorBody)
	}
	collectorID, ok := collector["id"].(string)
	if !ok || collectorID == "" {
		t.Fatalf("collector id missing: %s", collectorBody)
	}
	artifactDigest := "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
	artifactBody := postJSON(t, server, secret, "/v1/artifacts", "supply-artifact", map[string]any{"name": "evydence-collector", "media_type": "application/octet-stream", "digest": artifactDigest, "size": 6}, http.StatusCreated)
	artifactID := dataField(t, artifactBody, "id")
	sigBody := postJSON(t, server, secret, "/v1/artifact-signatures", "supply-signature", map[string]any{"artifact_id": artifactID, "algorithm": "cosign", "signature": "sig"}, http.StatusCreated)
	sigID := dataField(t, sigBody, "id")
	releaseBody := postJSON(t, server, secret, "/v1/collectors/"+collectorID+"/releases", "supply-release", map[string]any{"version": "0.1.0", "artifact_digest": artifactDigest, "signature_id": sigID, "pinned": true}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	health := getJSON(t, server, secret, "/v1/collectors/"+collectorID+"/health", http.StatusOK)
	if !strings.Contains(health, releaseID) || !strings.Contains(health, `"collector_version_pinned"`) {
		t.Fatalf("collector health response: %s", health)
	}
}

func TestControlsAndReportsHTTPFlow(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "ctrl-prod", map[string]any{"name": "Controls Product", "slug": "controls-product"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	releaseBody := postJSON(t, server, secret, "/v1/releases", "ctrl-rel", map[string]any{"product_id": productID, "version": "1.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	artifactBody := postJSON(t, server, secret, "/v1/artifacts", "ctrl-artifact", map[string]any{"name": "api.tar.gz", "media_type": "application/gzip", "digest": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "size": 42}, http.StatusCreated)
	artifactID := dataField(t, artifactBody, "id")
	sbomBody := postJSON(t, server, secret, "/v1/sboms", "ctrl-sbom", map[string]any{
		"release_id":  releaseID,
		"artifact_id": artifactID,
		"payload": map[string]any{
			"bomFormat": "CycloneDX", "specVersion": "1.6",
			"components": []map[string]any{{"name": "api", "purl": "pkg:oci/payments-api"}},
		},
	}, http.StatusCreated)
	sbomID := dataField(t, sbomBody, "id")
	frameworkBody := postJSON(t, server, secret, "/v1/control-frameworks", "ctrl-framework", map[string]any{"name": "CRA readiness", "slug": "evydence-cra-readiness", "version": "2026.05"}, http.StatusCreated)
	frameworkID := dataField(t, frameworkBody, "id")
	replayed := postJSON(t, server, secret, "/v1/control-frameworks", "ctrl-framework", map[string]any{"name": "CRA readiness", "slug": "evydence-cra-readiness", "version": "2026.05"}, http.StatusCreated)
	if replayed != frameworkBody {
		t.Fatalf("framework idempotency replay changed response\nfirst=%s\nsecond=%s", frameworkBody, replayed)
	}
	frameworks := getJSON(t, server, secret, "/v1/control-frameworks", http.StatusOK)
	if !strings.Contains(frameworks, frameworkID) {
		t.Fatalf("framework list missing id %s: %s", frameworkID, frameworks)
	}
	postJSON(t, server, secret, "/v1/control-frameworks", "ctrl-framework-conflict", map[string]any{"name": "Changed", "slug": "evydence-cra-readiness", "version": "2026.05"}, http.StatusConflict)
	controlBody := postJSON(t, server, secret, "/v1/controls", "ctrl-control", map[string]any{
		"framework_id": frameworkID,
		"code":         "CRA-SBOM",
		"title":        "SBOM evidence exists",
		"objective":    "Release records SBOM evidence.",
		"evidence_requirements": []map[string]any{{
			"type":           "sbom",
			"freshness_days": 90,
			"required":       true,
		}},
		"limitations": []string{"Presence does not prove completeness."},
	}, http.StatusCreated)
	controlID := dataField(t, controlBody, "id")
	getJSON(t, server, secret, "/v1/controls/"+controlID, http.StatusOK)
	postJSON(t, server, secret, "/v1/controls", "ctrl-control-bad", map[string]any{"framework_id": frameworkID, "code": "BAD", "title": "Bad", "objective": "Bad", "evidence_requirements": []map[string]any{{"type": "unknown", "required": true}}}, http.StatusBadRequest)
	report := getJSON(t, server, secret, "/v1/reports/control-coverage?framework_id="+frameworkID+"&product_id="+productID+"&release_id="+releaseID, http.StatusOK)
	if !strings.Contains(report, `"status":"missing"`) {
		t.Fatalf("expected missing control before link: %s", report)
	}
	linkBody := postJSON(t, server, secret, "/v1/controls/"+controlID+"/evidence", "ctrl-link", map[string]any{
		"evidence_type": "sbom",
		"subject_type":  "sbom",
		"subject_id":    sbomID,
		"product_id":    productID,
		"release_id":    releaseID,
		"confidence":    "high",
	}, http.StatusCreated)
	linkReplay := postJSON(t, server, secret, "/v1/controls/"+controlID+"/evidence", "ctrl-link", map[string]any{
		"evidence_type": "sbom",
		"subject_type":  "sbom",
		"subject_id":    sbomID,
		"product_id":    productID,
		"release_id":    releaseID,
		"confidence":    "high",
	}, http.StatusCreated)
	if linkReplay != linkBody {
		t.Fatalf("control evidence idempotency replay changed response\nfirst=%s\nsecond=%s", linkBody, linkReplay)
	}
	getJSON(t, server, secret, "/v1/control-evidence?control_id="+controlID+"&release_id="+releaseID, http.StatusOK)
	report = getJSON(t, server, secret, "/v1/reports/control-coverage?framework_id="+frameworkID+"&product_id="+productID+"&release_id="+releaseID, http.StatusOK)
	if !strings.Contains(report, `"status":"satisfied"`) || !strings.Contains(report, `"confidence":"high"`) {
		t.Fatalf("expected satisfied control after link: %s", report)
	}
	cra := getJSON(t, server, secret, "/v1/reports/cra-readiness?product_id="+productID+"&release_id="+releaseID, http.StatusOK)
	if strings.Contains(strings.ToLower(cra), "automatically compliant") || strings.Contains(strings.ToLower(cra), "certified secure") {
		t.Fatalf("CRA report contains forbidden claim: %s", cra)
	}
}

func TestEvidenceLifecycleSourceDeploymentHTTPFlow(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "inc-prod", map[string]any{"name": "Increment Product", "slug": "increment-product"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	projectBody := postJSON(t, server, secret, "/v1/projects", "inc-project", map[string]any{"product_id": productID, "name": "api"}, http.StatusCreated)
	projectID := dataField(t, projectBody, "id")
	releaseBody := postJSON(t, server, secret, "/v1/releases", "inc-release", map[string]any{"product_id": productID, "version": "3.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	digest := "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	artifactBody := postJSON(t, server, secret, "/v1/artifacts", "inc-artifact", map[string]any{"name": "api.tar.gz", "media_type": "application/gzip", "digest": digest, "size": 42}, http.StatusCreated)
	artifactID := dataField(t, artifactBody, "id")
	evidenceBody := postJSON(t, server, secret, "/v1/evidence", "inc-evidence", map[string]any{
		"release_id": releaseID, "type": "build", "subtype": "log", "title": "Build", "payload_hash": digest, "tags": []string{"ci"},
	}, http.StatusCreated)
	evidenceID := dataField(t, evidenceBody, "id")
	search := getJSON(t, server, secret, "/v1/evidence/search?release_id="+releaseID+"&type=build&tag=ci&limit=10", http.StatusOK)
	if !strings.Contains(search, evidenceID) {
		t.Fatalf("evidence search missing evidence id %s: %s", evidenceID, search)
	}
	postJSON(t, server, secret, "/v1/evidence/"+evidenceID+"/lifecycle-events", "inc-life", map[string]any{"action": "redaction", "reason": "redacted from external package"}, http.StatusCreated)
	events := getJSON(t, server, secret, "/v1/evidence/"+evidenceID+"/lifecycle-events", http.StatusOK)
	if !strings.Contains(events, `"action":"redaction"`) {
		t.Fatalf("lifecycle events missing redaction: %s", events)
	}
	rcBody := postJSON(t, server, secret, "/v1/release-candidates", "inc-rc", map[string]any{"release_id": releaseID, "name": "rc.1", "artifact_ids": []string{artifactID}}, http.StatusCreated)
	rcID := dataField(t, rcBody, "id")
	getJSON(t, server, secret, "/v1/release-candidates/"+rcID, http.StatusOK)
	getJSON(t, server, secret, "/v1/release-candidates?release_id="+releaseID, http.StatusOK)
	postJSON(t, server, secret, "/v1/release-candidates/"+rcID+"/promote", "inc-rc-promote", map[string]any{"reason": "accepted"}, http.StatusOK)
	rejectedRCBody := postJSON(t, server, secret, "/v1/release-candidates", "inc-rc-reject", map[string]any{"release_id": releaseID, "name": "rc.reject", "artifact_ids": []string{artifactID}}, http.StatusCreated)
	postJSON(t, server, secret, "/v1/release-candidates/"+dataField(t, rejectedRCBody, "id")+"/reject", "inc-rc-reject-transition", map[string]any{"reason": "superseded"}, http.StatusOK)
	postJSON(t, server, secret, "/v1/container-images", "inc-image", map[string]any{"artifact_id": artifactID, "repository": "ghcr.io/example/api", "tag": "3.0.0", "digest": digest, "platform": "linux/amd64"}, http.StatusCreated)
	sigBody := postJSON(t, server, secret, "/v1/artifact-signatures", "inc-sig", map[string]any{"artifact_id": artifactID, "algorithm": "cosign", "key_id": "test", "signature": "c2ln", "payload": map[string]any{"sig": "c2ln"}}, http.StatusCreated)
	sigID := dataField(t, sigBody, "id")
	getJSON(t, server, secret, "/v1/artifact-signatures/"+sigID, http.StatusOK)

	repoBody := postJSON(t, server, secret, "/v1/source/repositories", "inc-repo", map[string]any{"project_id": projectID, "provider": "github", "full_name": "example/api", "clone_url": "https://github.com/example/api.git", "default_branch": "main"}, http.StatusCreated)
	repoID := dataField(t, repoBody, "id")
	commitBody := postJSON(t, server, secret, "/v1/source/commits", "inc-commit", map[string]any{"repository_id": repoID, "sha": "0123456789abcdef0123456789abcdef01234567", "author": "dev@example.test", "message": "change", "committed_at": "2026-05-28T10:00:00Z"}, http.StatusCreated)
	commitID := dataField(t, commitBody, "id")
	postJSON(t, server, secret, "/v1/source/branches", "inc-branch", map[string]any{"repository_id": repoID, "name": "main", "head_commit_id": commitID, "protected": true, "protection_hash": digest}, http.StatusCreated)
	postJSON(t, server, secret, "/v1/source/pull-requests", "inc-pr", map[string]any{"repository_id": repoID, "provider_id": "42", "title": "Change", "state": "merged", "source_branch": "feature", "target_branch": "main", "head_commit_id": commitID}, http.StatusCreated)
	getJSON(t, server, secret, "/v1/source/repositories?project_id="+projectID, http.StatusOK)

	envBody := postJSON(t, server, secret, "/v1/environments", "inc-env", map[string]any{"product_id": productID, "name": "production", "kind": "production"}, http.StatusCreated)
	envID := dataField(t, envBody, "id")
	envs := getJSON(t, server, secret, "/v1/environments?product_id="+productID, http.StatusOK)
	if !strings.Contains(envs, envID) {
		t.Fatalf("environment list missing id %s: %s", envID, envs)
	}
	deploymentBody := postJSON(t, server, secret, "/v1/deployments", "inc-deploy", map[string]any{"environment_id": envID, "release_id": releaseID, "artifact_ids": []string{artifactID}, "status": "succeeded", "started_at": "2026-05-28T12:00:00Z"}, http.StatusCreated)
	deploymentID := dataField(t, deploymentBody, "id")
	getJSON(t, server, secret, "/v1/deployments/"+deploymentID, http.StatusOK)
	getJSON(t, server, secret, "/v1/deployments?release_id="+releaseID+"&environment_id="+envID, http.StatusOK)
}

func TestRiskWorkflowHTTPFlow(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "risk2-prod", map[string]any{"name": "Risk Product", "slug": "risk-product"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	releaseBody := postJSON(t, server, secret, "/v1/releases", "risk2-release", map[string]any{"product_id": productID, "version": "4.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	digest := "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	artifactBody := postJSON(t, server, secret, "/v1/artifacts", "risk2-artifact", map[string]any{"name": "api.tar.gz", "media_type": "application/gzip", "digest": digest, "size": 42}, http.StatusCreated)
	artifactID := dataField(t, artifactBody, "id")

	incidentBody := postJSON(t, server, secret, "/v1/incidents", "risk2-incident", map[string]any{"product_id": productID, "release_id": releaseID, "title": "API outage", "severity": "high"}, http.StatusCreated)
	incidentID := dataField(t, incidentBody, "id")
	postJSON(t, server, secret, "/v1/incidents/"+incidentID+"/timeline", "risk2-timeline", map[string]any{"event_type": "detected", "summary": "monitor alert"}, http.StatusCreated)
	webhookPublic, webhookPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("webhook key: %v", err)
	}
	receiverBody := postJSON(t, server, secret, "/v1/incidents/"+incidentID+"/webhook-receivers", "risk2-webhook-receiver", map[string]any{"name": "pager", "provider": "incident_tool", "public_key": base64.RawStdEncoding.EncodeToString(webhookPublic)}, http.StatusCreated)
	webhookBody := signedIncidentWebhook(t, server, dataField(t, receiverBody, "id"), webhookPrivate, "evt-http-1", []byte(`{"event_type":"mitigation_applied","summary":"patched service"}`), http.StatusCreated)
	if !strings.Contains(webhookBody, `"event_type":"mitigation_applied"`) || strings.Contains(webhookBody, base64.RawStdEncoding.EncodeToString(webhookPrivate)) {
		t.Fatalf("webhook response invalid: %s", webhookBody)
	}
	postJSON(t, server, secret, "/v1/remediation-tasks", "risk2-task", map[string]any{"incident_id": incidentID, "title": "patch", "owner": "security"}, http.StatusCreated)
	incidentReport := getJSON(t, server, secret, "/v1/reports/incident-package?incident_id="+incidentID, http.StatusOK)
	if !strings.Contains(incidentReport, `"report_type":"incident_package"`) {
		t.Fatalf("incident report missing type: %s", incidentReport)
	}

	scanBody := postJSON(t, server, secret, "/v1/security-scans", "risk2-secscan", map[string]any{
		"product_id": productID, "release_id": releaseID, "artifact_id": artifactID, "category": "secret_scan", "format": "generic", "scanner": "trufflehog", "target_ref": digest,
		"payload": map[string]any{"findings": []map[string]any{{"severity": "high"}}},
	}, http.StatusCreated)
	if !strings.Contains(scanBody, `"quarantined":true`) {
		t.Fatalf("secret scan should be quarantined: %s", scanBody)
	}
	postJSON(t, server, secret, "/v1/api-security-scans", "risk2-api-scan", map[string]any{
		"product_id": productID, "release_id": releaseID, "format": "sarif", "scanner": "spectral", "target_ref": "openapi",
		"payload": map[string]any{"version": "2.1.0", "runs": []map[string]any{{"results": []map[string]any{{"level": "warning"}}}}},
	}, http.StatusCreated)
	postJSON(t, server, secret, "/v1/security-documents", "risk2-doc", map[string]any{"product_id": productID, "release_id": releaseID, "document_type": "pen_test_report", "title": "Pen test", "sensitivity": "restricted", "payload": map[string]any{"summary": "manual evidence"}}, http.StatusCreated)

	baseSBOM := postJSON(t, server, secret, "/v1/sboms/spdx", "risk2-spdx-base", map[string]any{"release_id": releaseID, "artifact_id": artifactID, "payload": map[string]any{"spdxVersion": "SPDX-2.3", "packages": []map[string]any{{"name": "openssl", "versionInfo": "3.1.0"}}}}, http.StatusCreated)
	targetSBOM := postJSON(t, server, secret, "/v1/sboms/spdx", "risk2-spdx-target", map[string]any{"release_id": releaseID, "artifact_id": artifactID, "payload": map[string]any{"spdxVersion": "SPDX-2.3", "packages": []map[string]any{{"name": "openssl", "versionInfo": "3.1.0"}, {"name": "curl", "versionInfo": "8.0.0"}}}}, http.StatusCreated)
	diffBody := postJSON(t, server, secret, "/v1/sbom-diffs", "risk2-sbom-diff", map[string]any{"base_sbom_id": dataField(t, baseSBOM, "id"), "target_sbom_id": dataField(t, targetSBOM, "id"), "release_id": releaseID}, http.StatusCreated)
	if !strings.Contains(diffBody, `"added_components"`) {
		t.Fatalf("sbom diff missing added components: %s", diffBody)
	}
	componentSearch := getJSON(t, server, secret, "/v1/sbom-components?release_id="+releaseID+"&query=curl&limit=10", http.StatusOK)
	if !strings.Contains(componentSearch, `"name":"curl"`) {
		t.Fatalf("sbom component search missing curl: %s", componentSearch)
	}

	vulnScan := postJSON(t, server, secret, "/v1/vulnerability-scans", "risk2-vuln-scan", map[string]any{"scanner": "grype", "target_ref": "pkg:oci/api", "release_id": releaseID, "findings": []map[string]any{{"vulnerability": "CVE-2026-4242", "component": "openssl", "severity": "critical", "state": "open"}}}, http.StatusCreated)
	findingID := firstFindingID(t, vulnScan)
	postJSON(t, server, secret, "/v1/vex/cyclonedx", "risk2-cdx-vex", map[string]any{"release_id": releaseID, "artifact_id": artifactID, "payload": map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": []map[string]any{{"id": "CVE-2026-4242", "analysis": map[string]any{"state": "resolved", "justification": "code_not_present", "detail": "fixed", "response": []string{"update"}}}}}}, http.StatusCreated)
	postJSON(t, server, secret, "/v1/vulnerability-findings/"+findingID+"/workflow", "risk2-vuln-flow", map[string]any{"action": "scanner_disagreement", "reason": "secondary scanner found no issue"}, http.StatusCreated)
	getJSON(t, server, secret, "/v1/reports/vulnerability-posture?release_id="+releaseID, http.StatusOK)

	baseContract := postJSON(t, server, secret, "/v1/openapi-contracts", "risk2-oas-base", map[string]any{"product_id": productID, "release_id": releaseID, "version": "1", "spec": map[string]any{"openapi": "3.1.0", "info": map[string]any{"title": "API", "version": "1"}, "paths": map[string]any{"/v1/a": map[string]any{"get": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "ok"}}}}}}}, http.StatusCreated)
	targetContract := postJSON(t, server, secret, "/v1/openapi-contracts", "risk2-oas-target", map[string]any{"product_id": productID, "release_id": releaseID, "version": "2", "spec": map[string]any{"openapi": "3.1.0", "info": map[string]any{"title": "API", "version": "2"}, "paths": map[string]any{}}}, http.StatusCreated)
	contractDiff := postJSON(t, server, secret, "/v1/openapi-diffs", "risk2-oas-diff", map[string]any{"base_contract_id": dataField(t, baseContract, "id"), "target_contract_id": dataField(t, targetContract, "id"), "release_id": releaseID}, http.StatusCreated)
	if !strings.Contains(contractDiff, `"result":"breaking"`) {
		t.Fatalf("contract diff should be breaking: %s", contractDiff)
	}

	policyBody := postJSON(t, server, secret, "/v1/custom-policies", "risk2-policy", map[string]any{"name": "release custom", "version": "1", "rules": []map[string]any{{"name": "requires sbom", "evidence_type": "sbom", "severity": "high", "required": true}}}, http.StatusCreated)
	eval := postJSON(t, server, secret, "/v1/custom-policies/"+dataField(t, policyBody, "id")+"/evaluate", "risk2-policy-eval", map[string]any{"release_id": releaseID}, http.StatusCreated)
	if !strings.Contains(eval, `"result":"passed"`) {
		t.Fatalf("custom policy should pass after sbom upload: %s", eval)
	}
}

func TestGovernancePackageAndBundleHTTPFlow(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "gov-prod", map[string]any{"name": "Gov Product", "slug": "gov-product"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	releaseBody := postJSON(t, server, secret, "/v1/releases", "gov-release", map[string]any{"product_id": productID, "version": "5.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	evidenceBody := postJSON(t, server, secret, "/v1/evidence", "gov-evidence", map[string]any{"product_id": productID, "release_id": releaseID, "type": "security_review", "title": "Review", "payload_hash": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}, http.StatusCreated)
	evidenceID := dataField(t, evidenceBody, "id")

	packs := getJSON(t, server, secret, "/v1/control-framework-template-packs", http.StatusOK)
	if !strings.Contains(packs, "evydence-cra-readiness") {
		t.Fatalf("template packs missing CRA pack: %s", packs)
	}
	postJSON(t, server, secret, "/v1/control-framework-template-packs/evydence-cra-readiness/install", "gov-install-pack", map[string]any{}, http.StatusCreated)
	waiverBody := postJSON(t, server, secret, "/v1/waivers", "gov-waiver", map[string]any{"scope_type": "release", "scope_id": releaseID, "owner": "security", "risk": "accepted", "reason": "temporary", "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, http.StatusCreated)
	waiverID := dataField(t, waiverBody, "id")
	postJSON(t, server, secret, "/v1/waivers/"+waiverID+"/approve", "gov-waiver-approve", map[string]any{}, http.StatusOK)
	postJSON(t, server, secret, "/v1/approvals", "gov-approval", map[string]any{"subject_type": "waiver", "subject_id": waiverID, "decision": "approved", "reason": "accepted", "evidence_id": evidenceID}, http.StatusCreated)

	profileBody := postJSON(t, server, secret, "/v1/redaction-profiles", "gov-profile", map[string]any{"name": "customer", "allowed_types": []string{"security_review"}, "excluded_fields": []string{"payload_ref"}}, http.StatusCreated)
	profileID := dataField(t, profileBody, "id")
	packageBody := postJSON(t, server, secret, "/v1/customer-packages", "gov-package", map[string]any{"product_id": productID, "release_id": releaseID, "redaction_profile_id": profileID, "title": "Customer package", "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, http.StatusCreated)
	packageID := dataField(t, packageBody, "id")
	getJSON(t, server, secret, "/v1/customer-packages/"+packageID, http.StatusOK)
	archiveRec := getRaw(t, server, secret, "/v1/customer-packages/"+packageID+"/download", http.StatusOK)
	if archiveRec.Header().Get("Content-Type") != "application/zip" || !bytes.HasPrefix(archiveRec.Body.Bytes(), []byte("PK")) || archiveRec.Header().Get("X-Evydence-Archive-Hash") == "" {
		t.Fatalf("customer package archive response invalid headers=%v len=%d", archiveRec.Header(), archiveRec.Body.Len())
	}
	packageReport := getJSON(t, server, secret, "/v1/reports/security-review-package?package_id="+packageID, http.StatusOK)
	if !strings.Contains(packageReport, `"report_type":"security_review_package"`) {
		t.Fatalf("security review report missing type: %s", packageReport)
	}
	htmlReport := getJSON(t, server, secret, "/v1/reports/cra-readiness-html?product_id="+productID+"&release_id="+releaseID, http.StatusOK)
	if !strings.Contains(htmlReport, `"report_type":"cra_readiness"`) {
		t.Fatalf("CRA HTML package missing report type: %s", htmlReport)
	}
	templateBody := postJSON(t, server, secret, "/v1/report-templates", "gov-report-template", map[string]any{"name": "simple", "version": "1", "report_type": "summary", "allowed_fields": []string{"subject_type", "subject_id"}, "template": "json"}, http.StatusCreated)
	templateID := dataField(t, templateBody, "id")
	postJSON(t, server, secret, "/v1/report-templates/"+templateID+"/render", "gov-report-render", map[string]any{"subject_type": "release", "subject_id": releaseID}, http.StatusCreated)
	bundleBody := postJSON(t, server, secret, "/v1/evidence-bundles", "gov-bundle", map[string]any{"release_id": releaseID}, http.StatusCreated)
	bundle := dataMap(t, bundleBody)
	postJSON(t, server, secret, "/v1/evidence-bundles/import", "gov-bundle-import", bundle, http.StatusCreated)
	postJSON(t, server, secret, "/v1/dsse-trust-roots", "gov-bad-root", map[string]any{"name": "bad", "key_id": "root", "algorithm": "Ed25519", "public_key": "bad"}, http.StatusBadRequest)
}

func TestEnterprisePortalRetentionAndCommercialCollectorHTTPFlow(t *testing.T) {
	server, secret := testServer(t)
	orgBody := postJSON(t, server, secret, "/v1/organizations", "ent-org", map[string]any{"name": "Example", "slug": "example"}, http.StatusCreated)
	orgID := dataField(t, orgBody, "id")
	userBody := postJSON(t, server, secret, "/v1/users", "ent-user", map[string]any{"organization_id": orgID, "email": "Admin@Example.test", "display_name": "Admin"}, http.StatusCreated)
	userID := dataField(t, userBody, "id")
	postJSON(t, server, secret, "/v1/role-bindings", "ent-role", map[string]any{"subject_type": "user", "subject_id": userID, "role": "tenant_admin", "resource_type": "tenant"}, http.StatusCreated)
	providerBody := postJSON(t, server, secret, "/v1/sso/providers", "ent-sso", map[string]any{"name": "Okta", "type": "oidc", "issuer": "https://idp.example.test", "client_id": "client"}, http.StatusCreated)
	providerID := dataField(t, providerBody, "id")
	postJSON(t, server, secret, "/v1/sso/identity-links", "ent-link", map[string]any{"user_id": userID, "provider_id": providerID, "subject": "sub-1", "email": "admin@example.test", "verified": true}, http.StatusCreated)
	sessionBody := postJSON(t, server, secret, "/v1/sso/sessions", "ent-session", map[string]any{"user_id": userID, "provider_id": providerID, "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, http.StatusCreated)
	sessionSecret := nestedDataField(t, sessionBody, "secret")
	if strings.Contains(getJSON(t, server, secret, "/v1/role-bindings", http.StatusOK), sessionSecret) {
		t.Fatalf("session secret leaked in role binding response")
	}
	getJSON(t, server, secret, "/v1/admin/instance", http.StatusForbidden)
	getJSON(t, server, sessionSecret, "/v1/admin/instance", http.StatusForbidden)

	productBody := postJSON(t, server, sessionSecret, "/v1/products", "ent-product", map[string]any{"name": "Enterprise Product", "slug": "enterprise-product"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	releaseBody := postJSON(t, server, sessionSecret, "/v1/releases", "ent-release", map[string]any{"product_id": productID, "version": "1.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	evidenceBody := postJSON(t, server, sessionSecret, "/v1/evidence", "ent-evidence", map[string]any{"product_id": productID, "release_id": releaseID, "type": "security_review", "title": "Review", "payload_hash": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}, http.StatusCreated)
	evidenceID := dataField(t, evidenceBody, "id")
	profileBody := postJSON(t, server, sessionSecret, "/v1/redaction-profiles", "ent-profile", map[string]any{"name": "customer", "allowed_types": []string{"security_review"}}, http.StatusCreated)
	profileID := dataField(t, profileBody, "id")
	packageBody := postJSON(t, server, sessionSecret, "/v1/customer-packages", "ent-package", map[string]any{"product_id": productID, "release_id": releaseID, "redaction_profile_id": profileID, "title": "Customer package", "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, http.StatusCreated)
	packageID := dataField(t, packageBody, "id")
	accessBody := postJSON(t, server, sessionSecret, "/v1/customer-portal/access", "ent-access", map[string]any{"package_id": packageID, "customer_name": "ACME", "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, http.StatusCreated)
	portalSecret := nestedDataField(t, accessBody, "secret")
	portalBody := postJSONNoAuth(t, server, "/v1/customer-portal/package", map[string]any{"token": portalSecret}, http.StatusOK)
	if !strings.Contains(portalBody, packageID) || strings.Contains(portalBody, portalSecret) {
		t.Fatalf("portal package response invalid: %s", portalBody)
	}
	portalArchive := postJSONNoAuthRaw(t, server, "/v1/customer-portal/package/download", map[string]any{"token": portalSecret}, http.StatusOK)
	if portalArchive.Header().Get("Content-Type") != "application/zip" || !bytes.HasPrefix(portalArchive.Body.Bytes(), []byte("PK")) || bytes.Contains(portalArchive.Body.Bytes(), []byte(portalSecret)) {
		t.Fatalf("portal archive response invalid headers=%v len=%d", portalArchive.Header(), portalArchive.Body.Len())
	}
	postJSON(t, server, sessionSecret, "/v1/legal-holds", "ent-hold", map[string]any{"scope_type": "release", "scope_id": releaseID, "reason": "extended review", "owner": "legal"}, http.StatusCreated)
	postJSON(t, server, sessionSecret, "/v1/retention-overrides", "ent-retention", map[string]any{"scope_type": "evidence", "scope_id": evidenceID, "retention_until": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339), "reason": "review", "owner": "security"}, http.StatusCreated)
	retention := getJSON(t, server, sessionSecret, "/v1/reports/retention?scope_type=release&scope_id="+releaseID, http.StatusOK)
	if !strings.Contains(retention, `"legal_holds"`) {
		t.Fatalf("retention report missing legal holds: %s", retention)
	}
	templateBody := postJSON(t, server, sessionSecret, "/v1/questionnaire-templates", "ent-question-template", map[string]any{"name": "customer", "version": "1", "questions": []map[string]any{{"id": "q1", "prompt": "Is review evidence available?", "evidence_type": "security_review"}}}, http.StatusCreated)
	templateID := dataField(t, templateBody, "id")
	questionnaire := postJSON(t, server, sessionSecret, "/v1/questionnaire-packages", "ent-question-package", map[string]any{"template_id": templateID, "package_id": packageID, "product_id": productID, "release_id": releaseID}, http.StatusCreated)
	if !strings.Contains(questionnaire, evidenceID) {
		t.Fatalf("questionnaire package missing evidence id: %s", questionnaire)
	}
	collectorBody := postJSON(t, server, sessionSecret, "/v1/commercial-collectors", "ent-commercial-collector", map[string]any{"name": "jira", "provider": "jira", "version": "1.0.0", "manifest_hash": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "allowed_scopes": []string{"evidence:write"}}, http.StatusCreated)
	collectorID := dataField(t, collectorBody, "id")
	collectors := getJSON(t, server, sessionSecret, "/v1/commercial-collectors", http.StatusOK)
	if !strings.Contains(collectors, collectorID) {
		t.Fatalf("commercial collector list missing id: %s", collectors)
	}
	sessionID := dataFieldFromNestedObject(t, sessionBody, "session", "id")
	postJSON(t, server, secret, "/v1/sso/sessions/"+sessionID+"/revoke", "ent-session-revoke", map[string]any{}, http.StatusOK)
	getJSON(t, server, sessionSecret, "/v1/admin/instance", http.StatusUnauthorized)
	postJSON(t, server, secret, "/v1/users/"+userID+"/deactivate", "ent-user-deactivate", map[string]any{}, http.StatusOK)
}

func TestFutureExtensionAndReadAdminHTTPGaps(t *testing.T) {
	ledger := app.NewLedger(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*", app.ScopeInstanceAdmin})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	server, err := NewServer(ledger)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	productBody := postJSON(t, server, secret, "/v1/products", "future-product", map[string]any{"name": "Future Product", "slug": "future-product"}, http.StatusCreated)
	productID := dataField(t, productBody, "id")
	getJSON(t, server, secret, "/v1/products", http.StatusOK)
	postJSON(t, server, secret, "/v1/projects", "future-project", map[string]any{"product_id": productID, "name": "api"}, http.StatusCreated)
	releaseBody := postJSON(t, server, secret, "/v1/releases", "future-release", map[string]any{"product_id": productID, "version": "9.0.0"}, http.StatusCreated)
	releaseID := dataField(t, releaseBody, "id")
	getJSON(t, server, secret, "/v1/releases/"+releaseID, http.StatusOK)
	postJSON(t, server, secret, "/v1/releases/"+releaseID+"/freeze", "future-freeze", map[string]any{}, http.StatusOK)
	postJSON(t, server, secret, "/v1/releases/"+releaseID+"/approve", "future-approve", map[string]any{}, http.StatusOK)

	digest := "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	artifactBody := postJSON(t, server, secret, "/v1/artifacts", "future-artifact", map[string]any{"name": "api.tar.gz", "media_type": "application/gzip", "digest": digest, "size": 42}, http.StatusCreated)
	artifactID := dataField(t, artifactBody, "id")
	evidenceBody := postJSON(t, server, secret, "/v1/evidence", "future-evidence", map[string]any{"product_id": productID, "release_id": releaseID, "type": "security_review", "title": "Review", "payload_hash": digest, "subject_refs": []map[string]any{{"type": "artifact", "id": artifactID}}}, http.StatusCreated)
	evidenceID := dataField(t, evidenceBody, "id")
	replacementBody := postJSON(t, server, secret, "/v1/evidence", "future-evidence-replacement", map[string]any{"product_id": productID, "type": "security_review", "title": "Review replacement", "payload_hash": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"}, http.StatusCreated)
	replacementID := dataField(t, replacementBody, "id")
	getJSON(t, server, secret, "/v1/evidence?release_id="+releaseID+"&type=security_review", http.StatusOK)
	postJSON(t, server, secret, "/v1/evidence/"+replacementID+"/link", "future-link", map[string]any{"target_type": "release", "target_id": releaseID}, http.StatusCreated)
	postJSON(t, server, secret, "/v1/evidence/"+evidenceID+"/supersede", "future-supersede", map[string]any{"replacement_evidence_id": replacementID, "reason": "updated review"}, http.StatusCreated)
	summary := postJSON(t, server, secret, "/v1/evidence-summaries", "future-summary", map[string]any{"subject_type": "release", "subject_id": releaseID, "evidence_ids": []string{evidenceID, replacementID}}, http.StatusCreated)
	if !strings.Contains(summary, `"citations"`) {
		t.Fatalf("summary missing citations: %s", summary)
	}
	graph := postJSON(t, server, secret, "/v1/evidence-graph-snapshots", "future-graph", map[string]any{"product_id": productID, "release_id": releaseID}, http.StatusCreated)
	if !strings.Contains(graph, `"graph_hash"`) {
		t.Fatalf("graph missing hash: %s", graph)
	}

	templateBody := postJSON(t, server, secret, "/v1/questionnaire-templates", "future-q-template", map[string]any{"name": "customer", "version": "2", "questions": []map[string]any{{"id": "q1", "prompt": "Review?", "evidence_type": "security_review"}}}, http.StatusCreated)
	templateID := dataField(t, templateBody, "id")
	draft := postJSON(t, server, secret, "/v1/questionnaire-drafts", "future-q-draft", map[string]any{"template_id": templateID, "product_id": productID, "release_id": releaseID}, http.StatusCreated)
	if !strings.Contains(draft, evidenceID) {
		t.Fatalf("draft missing evidence reference: %s", draft)
	}
	pdf := postJSON(t, server, secret, "/v1/reports/pdf", "future-pdf", map[string]any{"report_type": "release_readiness", "product_id": productID, "release_id": releaseID, "title": "Readiness"}, http.StatusCreated)
	if !strings.Contains(pdf, `"payload_hash"`) {
		t.Fatalf("pdf report missing hash: %s", pdf)
	}
	anomaly := postJSON(t, server, secret, "/v1/reports/anomaly", "future-anomaly", map[string]any{"subject_type": "release", "subject_id": releaseID}, http.StatusCreated)
	if !strings.Contains(anomaly, `"limitations"`) {
		t.Fatalf("anomaly missing limitations: %s", anomaly)
	}

	sbomBody := postJSON(t, server, secret, "/v1/sboms", "future-sbom", map[string]any{"release_id": releaseID, "artifact_id": artifactID, "payload": map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []map[string]any{{"name": "api", "purl": "pkg:oci/api"}}}}, http.StatusCreated)
	sbomID := dataField(t, sbomBody, "id")
	getJSON(t, server, secret, "/v1/sboms/"+sbomID, http.StatusOK)
	scanBody := postJSON(t, server, secret, "/v1/vulnerability-scans", "future-vuln-scan", map[string]any{"scanner": "grype", "target_ref": "pkg:oci/api", "release_id": releaseID, "findings": []map[string]any{}}, http.StatusCreated)
	scanID := dataField(t, scanBody, "id")
	getJSON(t, server, secret, "/v1/vulnerability-scans/"+scanID, http.StatusOK)
	contractBody := postJSON(t, server, secret, "/v1/openapi-contracts", "future-oas", map[string]any{"product_id": productID, "release_id": releaseID, "version": "1", "spec": map[string]any{"openapi": "3.1.0", "info": map[string]any{"title": "API", "version": "1"}, "paths": map[string]any{"/health": map[string]any{"get": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "ok"}}}}}}}, http.StatusCreated)
	contractID := dataField(t, contractBody, "id")
	getJSON(t, server, secret, "/v1/openapi-contracts/"+contractID, http.StatusOK)
	postJSON(t, server, secret, "/v1/policies/evaluate", "future-policy", map[string]any{"release_id": releaseID}, http.StatusCreated)
	getJSON(t, server, secret, "/v1/reports/missing-evidence?release_id="+releaseID, http.StatusOK)

	releaseBundle := postJSON(t, server, secret, "/v1/release-bundles", "future-release-bundle", map[string]any{"release_id": releaseID}, http.StatusCreated)
	bundleID := dataField(t, releaseBundle, "id")
	getJSON(t, server, secret, "/v1/release-bundles/"+bundleID, http.StatusOK)
	getJSON(t, server, secret, "/v1/release-bundles/"+bundleID+"/manifest", http.StatusOK)
	getJSON(t, server, secret, "/v1/audit-chain/verify", http.StatusOK)
	getJSON(t, server, secret, "/v1/signing-keys", http.StatusOK)
	keys := dataSlice(t, getJSON(t, server, secret, "/v1/signing-keys", http.StatusOK))
	keyID := keys[0]["id"].(string)
	postJSON(t, server, secret, "/v1/signing-keys/rotate", "future-key-rotate", map[string]any{"reason": "coverage"}, http.StatusCreated)
	postJSON(t, server, secret, "/v1/signing-keys/"+keyID+"/revoke", "future-key-revoke", map[string]any{"reason": "coverage"}, http.StatusOK)
	apiKeyBody := postJSON(t, server, secret, "/v1/api-keys", "future-api-key", map[string]any{"name": "reader", "scopes": []string{"evidence:read"}}, http.StatusCreated)
	if strings.Contains(getJSON(t, server, secret, "/v1/api-keys", http.StatusOK), nestedDataField(t, apiKeyBody, "secret")) {
		t.Fatalf("API key secret leaked in key list")
	}

	providerBody := postJSON(t, server, secret, "/v1/signing-providers", "future-provider", map[string]any{"name": "kms", "type": "aws_kms", "key_ref": "arn:aws:kms:example", "encrypted": true}, http.StatusCreated)
	providerID := dataField(t, providerBody, "id")
	op := postJSON(t, server, secret, "/v1/signing-operations", "future-sign-op", map[string]any{"provider_id": providerID, "subject_type": "release", "subject_id": releaseID, "payload_hash": digest, "external_signature": "sig"}, http.StatusCreated)
	if !strings.Contains(op, `"result":"passed"`) {
		t.Fatalf("signing operation did not pass: %s", op)
	}
	saas := postJSON(t, server, secret, "/v1/saas/profiles", "future-saas", map[string]any{"name": "hosted", "region": "eu", "admin_tenant_id": dataField(t, productBody, "tenant_id"), "isolation_model": "shared-control-plane"}, http.StatusCreated)
	if !strings.Contains(saas, `"config_hash"`) {
		t.Fatalf("saas profile missing hash: %s", saas)
	}

	logBody := postJSON(t, server, secret, "/v1/public-transparency-logs", "future-public-log", map[string]any{"name": "public", "endpoint": "https://transparency.example.test", "public_key": "pub"}, http.StatusCreated)
	logID := dataField(t, logBody, "id")
	batchBody := postJSON(t, server, secret, "/v1/merkle-batches", "future-batch", map[string]any{}, http.StatusCreated)
	batchID := dataField(t, batchBody, "id")
	checkpointBody := postJSON(t, server, secret, "/v1/transparency-checkpoints", "future-checkpoint", map[string]any{"batch_id": batchID, "provider": "internal", "external_id": "ts"}, http.StatusCreated)
	checkpointID := dataField(t, checkpointBody, "id")
	entry := postJSON(t, server, secret, "/v1/public-transparency-log-entries", "future-public-entry", map[string]any{"log_id": logID, "checkpoint_id": checkpointID, "external_id": "entry"}, http.StatusCreated)
	if !strings.Contains(entry, `"entry_hash"`) {
		t.Fatalf("public log entry missing hash: %s", entry)
	}
	marketplace := postJSON(t, server, secret, "/v1/marketplace-collectors", "future-marketplace", map[string]any{"name": "scanner", "provider": "scannerco", "version": "1.0.0", "publisher": "scannerco", "manifest_hash": digest}, http.StatusCreated)
	if !strings.Contains(getJSON(t, server, secret, "/v1/marketplace-collectors", http.StatusOK), dataField(t, marketplace, "id")) {
		t.Fatalf("marketplace list missing collector")
	}
	marketplaceHealth := getJSON(t, server, secret, "/v1/marketplace-collectors/"+dataField(t, marketplace, "id")+"/health", http.StatusOK)
	if !strings.Contains(marketplaceHealth, `"supply_chain_status":"incomplete"`) || strings.Contains(marketplaceHealth, secret) {
		t.Fatalf("marketplace health response: %s", marketplaceHealth)
	}

	orgBody := postJSON(t, server, secret, "/v1/organizations", "future-org", map[string]any{"name": "Example", "slug": "future-example"}, http.StatusCreated)
	userBody := postJSON(t, server, secret, "/v1/users", "future-user", map[string]any{"organization_id": dataField(t, orgBody, "id"), "email": "future@example.test", "display_name": "Future"}, http.StatusCreated)
	ssoBody := postJSON(t, server, secret, "/v1/sso/providers", "future-sso", map[string]any{"name": "OIDC", "type": "oidc", "issuer": "https://idp.example.test", "client_id": "client"}, http.StatusCreated)
	ssoID := dataField(t, ssoBody, "id")
	postJSON(t, server, secret, "/v1/sso/identity-links", "future-id-link", map[string]any{"user_id": dataField(t, userBody, "id"), "provider_id": ssoID, "subject": "sub-1", "email": "future@example.test", "verified": true}, http.StatusCreated)
	providerVerification := postJSON(t, server, secret, "/v1/provider-verifications", "future-provider-verification", map[string]any{"provider_type": "oidc", "provider_id": ssoID, "subject": "sub-1"}, http.StatusCreated)
	if !strings.Contains(providerVerification, `"result":"passed"`) {
		t.Fatalf("provider verification failed: %s", providerVerification)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("oidc keygen: %v", err)
	}
	jwks := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "kid-1", "alg": "EdDSA", "x": base64.RawURLEncoding.EncodeToString(pub)}}}
	signedProvider := postJSON(t, server, secret, "/v1/sso/providers", "future-sso-jwks", map[string]any{"name": "Signed OIDC", "type": "oidc", "issuer": "https://signed-idp.example.test", "client_id": "signed-client", "jwks": jwks}, http.StatusCreated)
	signedProviderID := dataField(t, signedProvider, "id")
	postJSON(t, server, secret, "/v1/sso/identity-links", "future-signed-link", map[string]any{"user_id": dataField(t, userBody, "id"), "provider_id": signedProviderID, "subject": "signed-sub", "email": "future@example.test", "verified": true}, http.StatusCreated)
	idToken := signedRouterIDToken(t, priv, "kid-1", map[string]any{"iss": "https://signed-idp.example.test", "aud": "signed-client", "sub": "signed-sub", "email": "future@example.test", "email_verified": true, "exp": time.Now().UTC().Add(time.Hour).Unix()})
	signedVerification := postJSON(t, server, secret, "/v1/provider-verifications", "future-provider-token-verification", map[string]any{"provider_type": "oidc", "provider_id": signedProviderID, "subject": "signed-sub", "id_token": idToken}, http.StatusCreated)
	if !strings.Contains(signedVerification, `"id_token_signature"`) || strings.Contains(signedVerification, idToken) {
		t.Fatalf("signed provider verification response: %s", signedVerification)
	}
}

func TestSourceSnapshotAndSystemHTTPGaps(t *testing.T) {
	server, secret := testServer(t)
	productBody := postJSON(t, server, secret, "/v1/products", "snapshot-product", map[string]any{"name": "Snapshot Product", "slug": "snapshot-product"}, http.StatusCreated)
	projectBody := postJSON(t, server, secret, "/v1/projects", "snapshot-project", map[string]any{"product_id": dataField(t, productBody, "id"), "name": "api"}, http.StatusCreated)
	projectID := dataField(t, projectBody, "id")
	payload := map[string]any{
		"project_id": projectID,
		"repository": map[string]any{"full_name": "aatuh/evydence", "clone_url": "https://github.com/aatuh/evydence.git", "default_branch": "main"},
		"commit":     map[string]any{"sha": "0123456789abcdef0123456789abcdef01234567", "author": "aatu", "message": "change", "committed_at": "2026-05-28T12:00:00Z"},
		"branch":     map[string]any{"name": "main", "protected": true, "protection_hash": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
		"pull_request": map[string]any{
			"provider_id": "42", "title": "Change", "state": "merged", "source_branch": "feature", "target_branch": "main", "review_decision": "approved",
		},
	}
	githubSnapshot := postJSON(t, server, secret, "/v1/collectors/github/source-snapshots", "snapshot-github", payload, http.StatusCreated)
	if !strings.Contains(githubSnapshot, `"repository_id"`) {
		t.Fatalf("github snapshot missing repository id: %s", githubSnapshot)
	}
	postJSON(t, server, secret, "/v1/collectors/gitlab/source-snapshots", "snapshot-gitlab", payload, http.StatusCreated)

	for _, path := range []string{"/v1/health", "/v1/version", "/v1/openapi.json"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/products", strings.NewReader(`{"name":`))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Idempotency-Key", "bad-json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "VALIDATION_FAILED") {
		t.Fatalf("bad JSON status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	ledger := app.NewLedger(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	server, err := NewServer(ledger)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	return server, secret
}

func postJSON(t *testing.T, server *Server, secret, path, idem string, payload any, want int) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Idempotency-Key", idem)
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("POST %s status=%d want=%d body=%s", path, rec.Code, want, rec.Body.String())
	}
	return rec.Body.String()
}

func postRaw(t *testing.T, server *Server, secret, path, idem string, body []byte, want int) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Idempotency-Key", idem)
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("POST %s status=%d want=%d body=%s", path, rec.Code, want, rec.Body.String())
	}
	return rec.Body.String()
}

func signedIncidentWebhook(t *testing.T, server *Server, receiverID string, private ed25519.PrivateKey, eventID string, body []byte, want int) string {
	t.Helper()
	timestamp := time.Now().UTC().Format(time.RFC3339)
	message := append([]byte(timestamp+"\n"+eventID+"\n"), body...)
	signature := ed25519.Sign(private, message)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/incident-webhooks/"+receiverID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Evydence-Webhook-Event-ID", eventID)
	req.Header.Set("X-Evydence-Webhook-Timestamp", timestamp)
	req.Header.Set("X-Evydence-Webhook-Signature", "ed25519="+base64.RawStdEncoding.EncodeToString(signature))
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("POST signed webhook status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
	}
	return rec.Body.String()
}

func postJSONNoAuth(t *testing.T, server *Server, path string, payload any, want int) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("POST %s status=%d want=%d body=%s", path, rec.Code, want, rec.Body.String())
	}
	return rec.Body.String()
}

func postJSONNoAuthRaw(t *testing.T, server *Server, path string, payload any, want int) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("POST %s status=%d want=%d body=%s", path, rec.Code, want, rec.Body.String())
	}
	return rec
}

func dataField(t *testing.T, body, field string) string {
	t.Helper()
	var decoded struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("unmarshal body: %v body=%s", err, body)
	}
	value, ok := decoded.Data[field].(string)
	if !ok || value == "" {
		t.Fatalf("field %s missing in %s", field, body)
	}
	return value
}

func dataMap(t *testing.T, body string) map[string]any {
	t.Helper()
	var decoded struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("unmarshal body: %v body=%s", err, body)
	}
	return decoded.Data
}

func dataSlice(t *testing.T, body string) []map[string]any {
	t.Helper()
	var decoded struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("unmarshal body: %v body=%s", err, body)
	}
	if len(decoded.Data) == 0 {
		t.Fatalf("data array is empty in %s", body)
	}
	return decoded.Data
}

func dataFieldFromNestedObject(t *testing.T, body, object, field string) string {
	t.Helper()
	data := dataMap(t, body)
	nested, ok := data[object].(map[string]any)
	if !ok {
		t.Fatalf("object %s missing in %s", object, body)
	}
	value, ok := nested[field].(string)
	if !ok || value == "" {
		t.Fatalf("field %s.%s missing in %s", object, field, body)
	}
	return value
}

func nestedDataField(t *testing.T, body, field string) string {
	t.Helper()
	var decoded struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("unmarshal body: %v body=%s", err, body)
	}
	value, ok := decoded.Data[field].(string)
	if !ok || value == "" {
		t.Fatalf("field %s missing in %s", field, body)
	}
	return value
}

func getJSON(t *testing.T, server *Server, secret, path string, want int) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("GET %s status=%d want=%d body=%s", path, rec.Code, want, rec.Body.String())
	}
	return rec.Body.String()
}

func getRaw(t *testing.T, server *Server, secret, path string, want int) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("GET %s status=%d want=%d body=%s", path, rec.Code, want, rec.Body.String())
	}
	return rec
}

func getRawWithAccept(t *testing.T, server *Server, secret, path, accept string, want int) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", accept)
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("GET %s status=%d want=%d body=%s", path, rec.Code, want, rec.Body.String())
	}
	return rec
}

func asStringAnyMap(t *testing.T, value any) map[string]any {
	t.Helper()
	out, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value is %T, want map[string]any: %#v", value, value)
	}
	return out
}

func asString(t *testing.T, value any) string {
	t.Helper()
	out, ok := value.(string)
	if !ok {
		t.Fatalf("value is %T, want string: %#v", value, value)
	}
	return out
}

func operationMap(t *testing.T, paths map[string]any, path, method string) map[string]any {
	t.Helper()
	pathItem := asStringAnyMap(t, paths[path])
	return asStringAnyMap(t, pathItem[method])
}

func assertRequestRef(t *testing.T, operation map[string]any, wantRef string) {
	t.Helper()
	body := asStringAnyMap(t, operation["requestBody"])
	content := asStringAnyMap(t, body["content"])
	media := asStringAnyMap(t, content["application/json"])
	schema := asStringAnyMap(t, media["schema"])
	if got := asString(t, schema["$ref"]); got != wantRef {
		t.Fatalf("request schema ref = %q, want %q", got, wantRef)
	}
}

func assertProblemResponseRef(t *testing.T, operation map[string]any, status string) {
	t.Helper()
	assertMediaResponseRef(t, operation, status, "application/problem+json", "#/components/schemas/Problem")
}

func assertResponseRef(t *testing.T, operation map[string]any, status, wantRef string) {
	t.Helper()
	assertMediaResponseRef(t, operation, status, "application/json", wantRef)
}

func assertMediaResponseRef(t *testing.T, operation map[string]any, status, mediaType, wantRef string) {
	t.Helper()
	responses := asStringAnyMap(t, operation["responses"])
	response := asStringAnyMap(t, responses[status])
	content := asStringAnyMap(t, response["content"])
	media := asStringAnyMap(t, content[mediaType])
	schema := asStringAnyMap(t, media["schema"])
	if got := asString(t, schema["$ref"]); got != wantRef {
		t.Fatalf("response schema ref = %q, want %q", got, wantRef)
	}
}

func assertMediaResponseType(t *testing.T, operation map[string]any, status, mediaType string) {
	t.Helper()
	responses := asStringAnyMap(t, operation["responses"])
	response := asStringAnyMap(t, responses[status])
	content := asStringAnyMap(t, response["content"])
	if _, ok := content[mediaType]; !ok {
		t.Fatalf("response %s missing media type %s: %#v", status, mediaType, content)
	}
}

func assertQueryParams(t *testing.T, operation map[string]any, names ...string) {
	t.Helper()
	rawParams, ok := operation["parameters"].([]any)
	if !ok {
		t.Fatalf("parameters missing: %#v", operation["parameters"])
	}
	got := map[string]bool{}
	for _, raw := range rawParams {
		param := asStringAnyMap(t, raw)
		got[asString(t, param["name"])] = true
	}
	for _, name := range names {
		if !got[name] {
			t.Fatalf("parameter %s missing from %#v", name, rawParams)
		}
	}
}

func firstFindingID(t *testing.T, body string) string {
	t.Helper()
	var decoded struct {
		Data struct {
			Findings []map[string]any `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("unmarshal scan body: %v body=%s", err, body)
	}
	if len(decoded.Data.Findings) == 0 {
		t.Fatalf("scan findings missing: %s", body)
	}
	id, ok := decoded.Data.Findings[0]["id"].(string)
	if !ok || id == "" {
		t.Fatalf("finding id missing: %s", body)
	}
	return id
}

func addHTTPBuildProvenance(t *testing.T, server *Server, secret, productID, releaseID, artifactID, artifactDigest string) {
	t.Helper()
	projectBody := postJSON(t, server, secret, "/v1/projects", "prov-"+releaseID, map[string]any{"product_id": productID, "name": "provenance"}, http.StatusCreated)
	projectID := dataField(t, projectBody, "id")
	buildBody := postJSON(t, server, secret, "/v1/builds", "build-"+releaseID, map[string]any{
		"project_id":   projectID,
		"release_id":   releaseID,
		"provider":     "github_actions",
		"commit_sha":   "0123456789abcdef0123456789abcdef01234567",
		"repository":   "aatuh/evydence",
		"workflow_ref": "aatuh/evydence/.github/workflows/release.yml@refs/heads/main",
		"run_id":       "123",
		"run_attempt":  1,
		"status":       "passed",
		"started_at":   "2026-05-27T12:00:00Z",
		"outputs":      []map[string]any{{"artifact_id": artifactID, "digest": artifactDigest}},
	}, http.StatusCreated)
	buildID := dataField(t, buildBody, "id")
	postRaw(t, server, secret, "/v1/builds/"+buildID+"/attestations", "att-"+releaseID, dsseHTTP(t, artifactDigest), http.StatusCreated)
}

func dsseHTTP(t *testing.T, digest string) []byte {
	t.Helper()
	statement := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{{
			"name":   "api.tar.gz",
			"digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")},
		}},
		"predicate": map[string]any{
			"builder":   map[string]string{"id": "https://github.com/actions/runner"},
			"buildType": "https://github.com/actions/workflow",
			"materials": []map[string]any{{"uri": "git+https://github.com/aatuh/evydence"}},
		},
	}
	statementBody, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	envelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(statementBody),
		"signatures":  []map[string]string{{"keyid": "test", "sig": "c2ln"}},
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return body
}

func signedRouterIDToken(t *testing.T, private ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	headerBody, err := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal jwt header: %v", err)
	}
	claimsBody, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal jwt claims: %v", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerBody) + "." + base64.RawURLEncoding.EncodeToString(claimsBody)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(unsigned)))
}
