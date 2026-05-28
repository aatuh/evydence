package httpgateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestNewRequiresHTTPSEndpointExceptLocalhostOverride(t *testing.T) {
	if _, err := New(Config{Endpoint: "http://example.com/sign"}); err == nil {
		t.Fatal("expected non-HTTPS remote endpoint to be rejected")
	}
	if _, err := New(Config{Endpoint: "http://127.0.0.1/sign", AllowInsecureForLocalhost: true}); err != nil {
		t.Fatalf("localhost override should be accepted: %v", err)
	}
}

func TestSignPostsHashOnlyAndReturnsSignature(t *testing.T) {
	var gotAuth, gotPayloadHash, gotKeyRef string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		gotAuth = r.Header.Get("Authorization")
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		gotPayloadHash = req.PayloadHash
		gotKeyRef = req.KeyRef
		_ = json.NewEncoder(w).Encode(signResponse{Signature: "sig_external", KeyID: "kms-key-1", Algorithm: "external-aws_kms"})
	}))
	defer server.Close()

	executor, err := New(Config{Endpoint: server.URL, BearerToken: "secret-token", AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Sign(t.Context(), app.SigningRequest{
		TenantID:     "ten_1",
		ProviderID:   "sp_1",
		ProviderType: "aws_kms",
		KeyRef:       "arn:aws:kms:example",
		SubjectType:  "release",
		SubjectID:    "rel_1",
		PayloadHash:  "sha256:abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Signature != "sig_external" || result.KeyID != "kms-key-1" || result.Algorithm != "external-aws_kms" {
		t.Fatalf("result = %#v", result)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotPayloadHash != "sha256:abcdef" || gotKeyRef != "arn:aws:kms:example" {
		t.Fatalf("request hash/key ref = %q/%q", gotPayloadHash, gotKeyRef)
	}
}

func TestSignRejectsUnknownResponseFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"signature":"sig","extra":"nope"}`))
	}))
	defer server.Close()
	executor, err := New(Config{Endpoint: server.URL, AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Sign(t.Context(), app.SigningRequest{PayloadHash: "sha256:abc"}); err == nil {
		t.Fatal("expected strict response decoding to reject unknown fields")
	}
}
