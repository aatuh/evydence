package httpapi

import (
	"bytes"
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

func TestUnknownJSONFieldReturnsProblem(t *testing.T) {
	server, secret := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/products", strings.NewReader(`{"name":"Payments","slug":"payments","extra":true}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Idempotency-Key", "unknown-field")
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"VALIDATION_FAILED"`) {
		t.Fatalf("problem code missing: %s", rec.Body.String())
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
	postRaw(t, server, collectorSecret, "/v1/builds/"+buildID+"/attestations", "prov-bad-attestation", []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"@@@","signatures":[{"sig":"abc"}]}`), http.StatusBadRequest)
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
	getJSON(t, server, secret, "/v1/release-candidates?release_id="+releaseID, http.StatusOK)
	postJSON(t, server, secret, "/v1/release-candidates/"+rcID+"/promote", "inc-rc-promote", map[string]any{"reason": "accepted"}, http.StatusOK)
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
