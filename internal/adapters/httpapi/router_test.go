package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
