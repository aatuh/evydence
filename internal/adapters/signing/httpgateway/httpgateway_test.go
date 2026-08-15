package httpgateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestNewRequiresHTTPSEndpointExceptLocalhostOverride(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	if _, err := New(Config{Endpoint: "http://example.com/sign", VerificationPublicKey: publicKey}); err == nil {
		t.Fatal("expected non-HTTPS remote endpoint to be rejected")
	}
	if _, err := New(Config{Endpoint: "http://127.0.0.1/sign", VerificationPublicKey: publicKey, AllowInsecureForLocalhost: true}); err != nil {
		t.Fatalf("localhost override should be accepted: %v", err)
	}
}

func TestSignPostsHashOnlyAndReturnsSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
		digest, err := hex.DecodeString(req.CanonicalPayloadHash[len("sha256:"):])
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(signResponse{Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest)), KeyID: "kms-key-1", Algorithm: "ed25519"})
	}))
	defer server.Close()

	executor, err := New(Config{Endpoint: server.URL, BearerToken: "secret-token", VerificationPublicKey: base64.StdEncoding.EncodeToString(publicKey), AllowInsecureForLocalhost: true})
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
		PayloadHash:  "sha256:abcdef", CanonicalPayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RequestID: "req_1", Nonce: "nonce_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Signature == "" || result.KeyID != "kms-key-1" || result.Algorithm != "ed25519" {
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
	executor, err := New(Config{Endpoint: server.URL, VerificationPublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)), AllowInsecureForLocalhost: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Sign(t.Context(), app.SigningRequest{PayloadHash: "sha256:abc"}); err == nil {
		t.Fatal("expected strict response decoding to reject unknown fields")
	}
}
