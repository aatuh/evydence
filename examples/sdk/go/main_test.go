package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestMainRunsCoreEvidenceFlow(t *testing.T) {
	type observedRequest struct {
		method         string
		path           string
		idempotencyKey string
	}
	var observed []observedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer example-secret" {
			t.Fatalf("unexpected auth header %q", got)
		}
		observed = append(observed, observedRequest{method: r.Method, path: r.URL.RequestURI(), idempotencyKey: r.Header.Get("Idempotency-Key")})
		if r.Method == http.MethodPost && strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
			t.Fatalf("missing idempotency key for %s", r.URL.Path)
		}

		var body map[string]any
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil && r.Method != http.MethodGet {
				t.Fatalf("decode request for %s: %v", r.URL.Path, err)
			}
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/products":
			assertField(t, body, "slug", "example-api")
			writeJSON(w, http.StatusCreated, map[string]any{"data": map[string]any{"id": "prod_1"}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/releases":
			assertField(t, body, "product_id", "prod_1")
			writeJSON(w, http.StatusCreated, map[string]any{"data": map[string]any{"id": "rel_1"}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/artifacts":
			assertField(t, body, "release_id", "rel_1")
			writeJSON(w, http.StatusCreated, map[string]any{"data": map[string]any{"id": "art_1"}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sboms":
			assertField(t, body, "artifact_id", "art_1")
			writeJSON(w, http.StatusCreated, map[string]any{"data": map[string]any{"id": "sbom_1"}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/vulnerability-scans":
			if _, ok := body["scanned_at"]; ok {
				t.Fatal("example sent unsupported scanned_at field")
			}
			assertField(t, body, "release_id", "rel_1")
			writeJSON(w, http.StatusCreated, map[string]any{"data": map[string]any{
				"id":       "scan_1",
				"findings": []map[string]any{{"id": "finding_1"}},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/vulnerability-findings/finding_1/decisions":
			assertField(t, body, "status", "not_affected")
			writeJSON(w, http.StatusCreated, map[string]any{"data": map[string]any{"id": "decision_1"}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/reports/release-readiness":
			if got := r.URL.Query().Get("release_id"); got != "rel_1" {
				t.Fatalf("unexpected release_id query %q", got)
			}
			writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"result": "failed"}})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer server.Close()

	t.Setenv("EVYDENCE_URL", server.URL)
	t.Setenv("EVYDENCE_API_KEY", "example-secret")

	stdout := os.Stdout
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	os.Stdout = devNull
	defer func() { os.Stdout = stdout }()

	main()

	wantPaths := []string{
		"/v1/products",
		"/v1/releases",
		"/v1/artifacts",
		"/v1/sboms",
		"/v1/vulnerability-scans",
		"/v1/vulnerability-findings/finding_1/decisions",
		"/v1/reports/release-readiness?release_id=rel_1",
	}
	if len(observed) != len(wantPaths) {
		t.Fatalf("observed %d requests, want %d: %#v", len(observed), len(wantPaths), observed)
	}
	for i, want := range wantPaths {
		if observed[i].path != want {
			t.Fatalf("request %d path = %q, want %q", i, observed[i].path, want)
		}
	}
}

func TestEnvelopeIDHelpersRejectUnexpectedShapes(t *testing.T) {
	assertPanics(t, func() { _ = id(map[string]any{}) })
	assertPanics(t, func() { _ = nestedID(map[string]any{"data": map[string]any{"findings": []any{}}}, "findings") })
}

func assertField(t *testing.T, body map[string]any, field, want string) {
	t.Helper()
	got, _ := body[field].(string)
	if got != want {
		t.Fatalf("%s = %q, want %q", field, got, want)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func assertPanics(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}
