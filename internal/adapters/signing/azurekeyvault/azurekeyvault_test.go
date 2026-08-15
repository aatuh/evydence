package azurekeyvault

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestSignSendsDigestOnlyToAzureKeyVault(t *testing.T) {
	var gotAuth string
	var gotPath string
	var gotQuery string
	var gotRequest signRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(signResponse{KeyID: serverKeyID(r), Value: base64.RawURLEncoding.EncodeToString([]byte("sig"))})
	}))
	defer server.Close()

	executor, err := New(Config{VaultURL: server.URL, AccessToken: "access-token", KeyName: "evydence", KeyVersion: "v1", Algorithm: "ES256", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Sign(t.Context(), app.SigningRequest{ProviderType: "azure_key_vault", PayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CanonicalPayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer access-token" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotPath != "/keys/evydence/v1/sign" || gotQuery != "api-version=7.4" {
		t.Fatalf("path/query = %q?%q", gotPath, gotQuery)
	}
	if gotRequest.Algorithm != "ES256" || gotRequest.Value != base64.RawURLEncoding.EncodeToString(bytesOf(0xaa, 32)) {
		t.Fatalf("request = %#v", gotRequest)
	}
	if result.Signature != base64.StdEncoding.EncodeToString([]byte("sig")) || result.Algorithm != "azure-key-vault:ES256" || len(result.Checks) == 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestSignCanUseKeyRefURL(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys/from-ref/v2/sign" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(signResponse{Value: base64.RawURLEncoding.EncodeToString([]byte("sig"))})
	}))
	defer server.Close()

	executor, err := New(Config{VaultURL: "https://unused.example.test", AccessToken: "access-token", KeyName: "evydence", KeyVersion: "v1", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.Sign(t.Context(), app.SigningRequest{ProviderType: "azure_key_vault", KeyRef: server.URL + "/keys/from-ref/v2", PayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CanonicalPayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignRejectsWrongProviderType(t *testing.T) {
	executor, err := New(Config{VaultURL: "https://vault.example.test", AccessToken: "token", KeyName: "evydence", KeyVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Sign(t.Context(), app.SigningRequest{ProviderType: "gcp_kms", PayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
		t.Fatal("expected wrong provider type to be rejected")
	}
}

func TestNewRequiresHTTPSAndAccessToken(t *testing.T) {
	if _, err := New(Config{VaultURL: "http://vault.example.test", AccessToken: "token"}); err == nil {
		t.Fatal("expected non-HTTPS vault URL to be rejected")
	}
	if _, err := New(Config{VaultURL: "https://vault.example.test"}); err == nil {
		t.Fatal("expected missing access token to be rejected")
	}
}

func serverKeyID(r *http.Request) string {
	return "https://" + r.Host + strings.TrimSuffix(r.URL.Path, "/sign")
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}
