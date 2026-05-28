package httpfetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestFetchTransparencyProofFetchesStrictJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/log/entries/entry-1/inclusion-proof" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"external_id":     "entry-1",
			"root_hash":       "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"leaf_index":      0,
			"tree_size":       1,
			"inclusion_proof": []string{},
		})
	}))
	defer server.Close()

	fetcher := New(Config{AllowInsecureForLocalhost: true})
	result, err := fetcher.FetchTransparencyProof(t.Context(), app.TransparencyProofRequest{Endpoint: server.URL + "/log", ExternalID: "entry-1"})
	if err != nil {
		t.Fatalf("FetchTransparencyProof: %v", err)
	}
	if result.ExternalID != "entry-1" || result.RootHash == "" || len(result.Checks) == 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestFetchTransparencyProofRejectsInsecureRemoteEndpoint(t *testing.T) {
	fetcher := New(Config{})
	if _, err := fetcher.FetchTransparencyProof(t.Context(), app.TransparencyProofRequest{Endpoint: "http://example.test/log", ExternalID: "entry-1"}); err == nil {
		t.Fatal("FetchTransparencyProof err=nil, want insecure endpoint rejection")
	}
}

func TestFetchTransparencyProofRejectsUnknownFieldsAndDoesNotLeakBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","leaf_index":0,"tree_size":1,"inclusion_proof":[],"provider_secret":"secret-value"}`))
	}))
	defer server.Close()

	fetcher := New(Config{AllowInsecureForLocalhost: true})
	_, err := fetcher.FetchTransparencyProof(t.Context(), app.TransparencyProofRequest{Endpoint: server.URL, ExternalID: "entry-1"})
	if err == nil {
		t.Fatal("FetchTransparencyProof err=nil, want strict JSON error")
	}
	if strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("error leaked provider body: %v", err)
	}
}
