package wiring

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
)

func TestPostgresNativeAPIRoutesNeverLoadAggregateState(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceRelationshipNative(t, p)
	// The snapshot-preferred fixture fails if any command/query tries to load
	// the compatibility aggregate. This is a canary, not a production profile.
	if _, err := p.Exec(t.Context(), `INSERT INTO ledger_state(id,state)VALUES('default','"aggregate-load-forbidden"')`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadState(t.Context()); err == nil {
		t.Fatal("aggregate-load canary is not active")
	}
	opts := subjectVerificationOptions(t, store, nil)
	opts.PaginationSecret = []byte("native-api-stable-cursor-test-key")
	opts.RateLimitRequestsPerMinute = 10000
	opts.ExpensiveTenantRequestsPerMinute = 10000
	s, err := httpapi.NewNativeServerWithOptionsContext(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateRoutes(); err != nil {
		t.Fatal(err)
	}
	spec, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(spec, &doc); err != nil {
		t.Fatal(err)
	}
	type operation struct{ id, method, path string }
	var operations []operation
	for path, methods := range doc.Paths {
		for method, op := range methods {
			if op.OperationID != "" {
				operations = append(operations, operation{op.OperationID, strings.ToUpper(method), path})
			}
		}
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].id < operations[j].id })
	if len(operations) != 189 {
		t.Fatalf("native route sweep covers %d operations, expected current contract's 189", len(operations))
	}
	parameters := regexp.MustCompile(`\{[^}]+\}`)
	for _, op := range operations {
		t.Run(op.id, func(t *testing.T) {
			path := parameters.ReplaceAllString(op.path, "missing")
			body := "{}"
			// Do not revoke the shared live session midway through a route sweep.
			if op.id == "logoutSSOSession" {
				body = `{"unknown":true}`
			}
			if op.method == http.MethodGet {
				body = ""
			}
			r := httptest.NewRequest(op.method, path, strings.NewReader(body)).WithContext(t.Context())
			r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
			r.Header.Set("Idempotency-Key", "sweep-"+op.id)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			// Public portal APIs use their own package token, not the supplied
			// administrative SSO bearer. Missing package tokens must still fail.
			portalTokenRequired := op.id == "accessCustomerPortalPackage" || op.id == "downloadCustomerPortalPackage"
			if portalTokenRequired && w.Code != http.StatusUnauthorized {
				t.Fatalf("portal accepted missing package token: status=%d", w.Code)
			}
			if w.Code >= 500 || w.Code == http.StatusUnauthorized && !portalTokenRequired || strings.Contains(w.Body.String(), "aggregate-load-forbidden") {
				t.Fatalf("native route reached an incomplete/aggregate dependency: status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	// Prove a valid, authenticated native write and restart replay also survive
	// the aggregate canary; malformed sweep requests alone cannot establish it.
	body := `{"name":"Native","slug":"native"}`
	request := func(server *httpapi.Server, raw, key string, want int) string {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/products", strings.NewReader(raw)).WithContext(t.Context())
		r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("native valid write status=%d want=%d body=%s", w.Code, want, w.Body.String())
		}
		return w.Body.String()
	}
	one := request(s, body, "valid-native", 201)
	restarted, err := httpapi.NewNativeServerWithOptionsContext(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	assertDeploymentCreationReplay(t, one, request(restarted, body, "valid-native", 201))
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request(restarted, body, "valid-native", 403)
	if _, _, err := store.LoadState(t.Context()); err == nil {
		t.Fatal("native writes replaced or disabled the aggregate-load canary")
	}
}
