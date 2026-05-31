package gcpkms

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestSignSendsDigestOnlyToGCPKMS(t *testing.T) {
	var gotAuth string
	var gotPath string
	var gotRequest signRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(signResponse{Signature: base64.StdEncoding.EncodeToString([]byte("sig")), Name: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"})
	}))
	defer server.Close()

	executor, err := New(Config{Endpoint: server.URL, AccessToken: "access-token", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Sign(t.Context(), app.SigningRequest{
		ProviderType: "gcp_kms",
		KeyRef:       "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
		PayloadHash:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer access-token" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if !strings.HasSuffix(gotPath, ":asymmetricSign") || !strings.Contains(gotPath, "/v1/projects/p/") {
		t.Fatalf("path = %q", gotPath)
	}
	if gotRequest.Digest.SHA256 != base64.StdEncoding.EncodeToString(bytesOf(0xaa, 32)) {
		t.Fatalf("digest = %q", gotRequest.Digest.SHA256)
	}
	if result.Signature == "" || result.Algorithm != "gcp-kms:asymmetric-sign-sha256" || len(result.Checks) == 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestSignRejectsWrongProviderType(t *testing.T) {
	executor, err := New(Config{Endpoint: "https://kms.example.test", AccessToken: "token", KeyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Sign(t.Context(), app.SigningRequest{ProviderType: "aws_kms", PayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
		t.Fatal("expected wrong provider type to be rejected")
	}
}

func TestNewRequiresHTTPSAndAccessToken(t *testing.T) {
	if _, err := New(Config{Endpoint: "http://kms.example.test", AccessToken: "token"}); err == nil {
		t.Fatal("expected non-HTTPS endpoint to be rejected")
	}
	if _, err := New(Config{Endpoint: "https://kms.example.test"}); err == nil {
		t.Fatal("expected missing access token to be rejected")
	}
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}
