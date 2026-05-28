package oidcdiscovery

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestFetchOIDCTrustMaterialFetchesDiscoveryAndJWKS(t *testing.T) {
	jwks := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "kid-1", "x": base64.RawURLEncoding.EncodeToString([]byte("public-key"))}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/issuer/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "http://" + r.Host + "/issuer", "jwks_uri": "http://" + r.Host + "/keys"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(Config{AllowInsecureForLocalhost: true})
	result, err := client.FetchOIDCTrustMaterial(t.Context(), app.OIDCDiscoveryRequest{TenantID: "ten_1", ProviderID: "sso_1", Issuer: server.URL + "/issuer"})
	if err != nil {
		t.Fatalf("FetchOIDCTrustMaterial: %v", err)
	}
	if result.Issuer != server.URL+"/issuer" || len(result.JWKS) == 0 || len(result.Checks) != 2 {
		t.Fatalf("result = %#v", result)
	}
}

func TestFetchOIDCTrustMaterialRejectsMismatchedIssuer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "http://localhost/other", "jwks_uri": "http://localhost/keys"})
	}))
	defer server.Close()

	client := New(Config{AllowInsecureForLocalhost: true})
	if _, err := client.FetchOIDCTrustMaterial(t.Context(), app.OIDCDiscoveryRequest{Issuer: server.URL}); err == nil {
		t.Fatal("FetchOIDCTrustMaterial err=nil, want error")
	}
}

func TestFetchOIDCTrustMaterialRequiresHTTPSUnlessLocalAllowed(t *testing.T) {
	client := New(Config{})
	if _, err := client.FetchOIDCTrustMaterial(t.Context(), app.OIDCDiscoveryRequest{Issuer: "http://127.0.0.1:8080/issuer"}); err == nil {
		t.Fatal("FetchOIDCTrustMaterial err=nil, want insecure issuer rejection")
	}
}

func TestFetchOIDCTrustMaterialDoesNotReturnRawProviderBodies(t *testing.T) {
	secretBody := `{"issuer":"bad","jwks_uri":"token-secret-value"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(secretBody))
	}))
	defer server.Close()

	client := New(Config{AllowInsecureForLocalhost: true})
	_, err := client.FetchOIDCTrustMaterial(t.Context(), app.OIDCDiscoveryRequest{Issuer: server.URL})
	if err == nil {
		t.Fatal("FetchOIDCTrustMaterial err=nil, want error")
	}
	if strings.Contains(err.Error(), "token-secret-value") {
		t.Fatalf("error leaked provider body: %v", err)
	}
}
