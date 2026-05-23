package httpapi

import (
	"bytes"
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
