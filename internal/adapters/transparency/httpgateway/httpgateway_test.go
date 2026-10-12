package httpgateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestFetchTransparencyProofPostsSafeRequestAndReturnsProof(t *testing.T) {
	var gotAuth string
	var gotRequest proofRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(proofResponse{
			ExternalID:     "entry-1",
			LeafHash:       testDigest,
			RootHash:       testDigest,
			LeafIndex:      0,
			TreeSize:       1,
			InclusionProof: []string{},
			Checks:         []domain.VerifyCheck{{Name: "provider_timestamp", Result: "passed"}},
			Limitations:    []string{"Gateway checked provider proof material."},
		})
	}))
	defer server.Close()

	fetcher, err := New(Config{Endpoint: server.URL, BearerToken: "gateway-token", AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err := fetcher.FetchTransparencyProof(t.Context(), app.TransparencyProofRequest{
		TenantID:   "ten_1",
		LogID:      "log_1",
		EntryID:    "pte_1",
		Endpoint:   "https://log.example.test",
		ExternalID: "entry-1",
		EntryHash:  testDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer gateway-token" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotRequest.ExternalID != "entry-1" || gotRequest.EntryHash != testDigest || gotRequest.Endpoint != "https://log.example.test" {
		t.Fatalf("request = %#v", gotRequest)
	}
	if result.RootHash != testDigest || len(result.Checks) < 2 || result.Checks[0].Name != "transparency_proof_gateway" {
		t.Fatalf("result = %#v", result)
	}
}

func TestFetchTransparencyProofRejectsExternalIDMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(proofResponse{ExternalID: "other", RootHash: testDigest, LeafIndex: 0, TreeSize: 1, InclusionProof: []string{}})
	}))
	defer server.Close()

	fetcher, err := New(Config{Endpoint: server.URL, AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.FetchTransparencyProof(t.Context(), app.TransparencyProofRequest{ExternalID: "entry-1"}); err == nil {
		t.Fatal("expected external id mismatch to fail")
	}
}

func TestFetchTransparencyProofRejectsUnknownFieldsAndHidesBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"external_id":"entry-1","root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","leaf_index":0,"tree_size":1,"inclusion_proof":[],"secret":"provider-secret"}`))
	}))
	defer server.Close()

	fetcher, err := New(Config{Endpoint: server.URL, AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fetcher.FetchTransparencyProof(t.Context(), app.TransparencyProofRequest{ExternalID: "entry-1"})
	if err == nil {
		t.Fatal("expected strict response decoding failure")
	}
	if strings.Contains(err.Error(), "provider-secret") {
		t.Fatalf("error leaked body: %v", err)
	}
}

func TestFetchTransparencyProofRejectsTrailingJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"external_id":"entry-1","root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","leaf_index":0,"tree_size":1,"inclusion_proof":[]}{"untrusted":"extra"}`))
	}))
	defer server.Close()

	fetcher, err := New(Config{Endpoint: server.URL, AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.FetchTransparencyProof(t.Context(), app.TransparencyProofRequest{ExternalID: "entry-1"}); err == nil {
		t.Fatal("trailing JSON response unexpectedly accepted")
	}
}

func TestNewRequiresHTTPSEndpointExceptLocalhostOverride(t *testing.T) {
	if _, err := New(Config{Endpoint: "http://example.com/proof"}); err == nil {
		t.Fatal("expected remote HTTP endpoint to be rejected")
	}
	if _, err := New(Config{Endpoint: "http://127.0.0.1/proof", AllowInsecureForLocalhost: true}); err != nil {
		t.Fatalf("localhost override should be accepted: %v", err)
	}
}
