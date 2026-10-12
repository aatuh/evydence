package azurekeyvault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/aatuh/evydence/internal/app"
)

type staticCredential string

func (c staticCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: string(c)}, nil
}

func TestSignSendsDigestOnlyToAzureKeyVault(t *testing.T) {
	var gotAuth string
	var gotPath string
	var gotQuery string
	var gotRequest signRequest
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(azureKeyResponse(serverKeyID(r), privateKey))
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Fatal(err)
		}
		digest, err := base64.RawURLEncoding.DecodeString(gotRequest.Value)
		if err != nil {
			t.Fatal(err)
		}
		rPart, sPart, err := ecdsa.Sign(rand.Reader, privateKey, digest)
		if err != nil {
			t.Fatal(err)
		}
		value := append(paddedSignaturePart(rPart), paddedSignaturePart(sPart)...)
		_ = json.NewEncoder(w).Encode(signResponse{KeyID: serverKeyID(r), Value: base64.RawURLEncoding.EncodeToString(value)})
	}))
	defer server.Close()

	executor, err := NewWithCredential(Config{VaultURL: server.URL, Credential: staticCredential("access-token"), KeyName: "evydence", KeyVersion: "v1", Algorithm: "ES256", Client: server.Client()})
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
	if gotPath != "/keys/evydence/v1" && gotPath != "/keys/evydence/v1/sign" || gotQuery != "api-version=7.4" {
		t.Fatalf("path/query = %q?%q", gotPath, gotQuery)
	}
	if gotRequest.Algorithm != "ES256" || gotRequest.Value != base64.RawURLEncoding.EncodeToString(bytesOf(0xaa, 32)) {
		t.Fatalf("request = %#v", gotRequest)
	}
	if result.Signature == "" || result.Algorithm != "azure-key-vault:ES256" || len(result.Checks) == 0 || result.Checks[0].Name != "azure_key_vault_signature_verified" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSignCanUseKeyRefURL(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(azureKeyResponse(serverKeyID(r), privateKey))
			return
		}
		if r.URL.Path != "/keys/from-ref/v2/sign" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		var request signRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		digest, err := base64.RawURLEncoding.DecodeString(request.Value)
		if err != nil {
			t.Fatal(err)
		}
		rPart, sPart, err := ecdsa.Sign(rand.Reader, privateKey, digest)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(signResponse{Value: base64.RawURLEncoding.EncodeToString(append(paddedSignaturePart(rPart), paddedSignaturePart(sPart)...))})
	}))
	defer server.Close()

	executor, err := NewWithCredential(Config{VaultURL: "https://unused.example.test", Credential: staticCredential("access-token"), KeyName: "evydence", KeyVersion: "v1", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.Sign(t.Context(), app.SigningRequest{ProviderType: "azure_key_vault", KeyRef: server.URL + "/keys/from-ref/v2", PayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CanonicalPayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignRejectsSignatureThatDoesNotVerifyWithProviderPublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(azureKeyResponse(serverKeyID(r), privateKey))
			return
		}
		_ = json.NewEncoder(w).Encode(signResponse{KeyID: serverKeyID(r), Value: base64.RawURLEncoding.EncodeToString([]byte("not-a-valid-signature"))})
	}))
	defer server.Close()
	executor, err := NewWithCredential(Config{VaultURL: server.URL, Credential: staticCredential("access-token"), KeyName: "evydence", KeyVersion: "v1", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Sign(t.Context(), app.SigningRequest{ProviderType: "azure_key_vault", CanonicalPayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
		t.Fatal("expected non-verifying provider signature to be rejected")
	}
}

func TestSignRejectsWrongProviderType(t *testing.T) {
	executor, err := NewWithCredential(Config{VaultURL: "https://vault.example.test", Credential: staticCredential("token"), KeyName: "evydence", KeyVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Sign(t.Context(), app.SigningRequest{ProviderType: "gcp_kms", PayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
		t.Fatal("expected wrong provider type to be rejected")
	}
}

func TestNewWithCredentialRequiresHTTPSAndCredential(t *testing.T) {
	if _, err := NewWithCredential(Config{VaultURL: "http://vault.example.test", Credential: staticCredential("token")}); err == nil {
		t.Fatal("expected non-HTTPS vault URL to be rejected")
	}
	if _, err := NewWithCredential(Config{VaultURL: "https://vault.example.test"}); err == nil {
		t.Fatal("expected missing credential to be rejected")
	}
}

func TestVerifySignatureRejectsMalformedAzurePublicKeyAndSignature(t *testing.T) {
	digest := bytesOf(0xaa, 32)
	if err := verifySignature(keyResponse{}, digest, base64.StdEncoding.EncodeToString([]byte("signature"))); err == nil {
		t.Fatal("expected missing Azure public key to be rejected")
	}
	malformed := keyResponse{}
	malformed.Key.KTY = "EC"
	malformed.Key.CRV = "P-256"
	malformed.Key.X = "not-base64"
	malformed.Key.Y = base64.RawURLEncoding.EncodeToString(bytesOf(1, 32))
	if err := verifySignature(malformed, digest, base64.StdEncoding.EncodeToString(bytesOf(1, 64))); err == nil {
		t.Fatal("expected malformed Azure coordinates to be rejected")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := azureKeyResponse("https://vault.example.test/keys/key/v1", privateKey)
	if err := verifySignature(valid, digest, base64.StdEncoding.EncodeToString(bytesOf(1, 63))); err == nil {
		t.Fatal("expected malformed Azure signature length to be rejected")
	}
}

func TestFetchPublicKeyClassifiesProviderFailuresWithoutResponseDetails(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("provider payload must not escape"))
			}))
			defer server.Close()
			executor, err := NewWithCredential(Config{VaultURL: server.URL, Credential: staticCredential("token"), KeyName: "key", KeyVersion: "v1", Client: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			_, err = executor.fetchPublicKey(t.Context(), server.URL+"/keys/key/v1", "token")
			if err == nil || strings.Contains(err.Error(), "provider payload") {
				t.Fatalf("err=%v, want safe provider failure", err)
			}
			if status >= 500 && !errors.Is(err, app.ErrRetryableSigning) {
				t.Fatalf("err=%v, want retryable failure", err)
			}
		})
	}
}

func TestAzureSigningHelpersRejectUnsafeValues(t *testing.T) {
	executor, err := NewWithCredential(Config{VaultURL: "https://vault.example.test", Credential: staticCredential("token"), KeyName: "key", KeyVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := executor.resolveKey("https://vault.example.test/keys/key/../v1"); err == nil {
		t.Fatal("expected traversal key reference to be rejected")
	}
	if _, err := decodePayloadHash("sha256:not-hex"); err == nil {
		t.Fatal("expected malformed digest to be rejected")
	}
	if _, err := normalizeBase64URLSignature("***"); err == nil {
		t.Fatal("expected malformed signature to be rejected")
	}
	response := &http.Response{Header: http.Header{"X-Ms-Request-Id": []string{strings.Repeat("a", 257)}}}
	if responseRequestID(response) != "" || firstNonEmpty("", "  chosen  ") != "chosen" {
		t.Fatal("expected unsafe request id to be discarded and value normalized")
	}
}

func TestSignClassifiesTransientAzureProviderFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	executor, err := NewWithCredential(Config{VaultURL: server.URL, Credential: staticCredential("token"), KeyName: "key", KeyVersion: "v1", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.Sign(t.Context(), app.SigningRequest{ProviderType: "azure_key_vault", CanonicalPayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if !errors.Is(err, app.ErrRetryableSigning) {
		t.Fatalf("err=%v, want retryable signing failure", err)
	}
}

func TestNewUsesDefaultCredentialChainBeforeValidatingVaultURL(t *testing.T) {
	if _, err := New(Config{VaultURL: "http://vault.example.test"}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("err=%v, want validation after creating default credential chain", err)
	}
}

func TestNewWithCredentialRejectsUnsupportedAzureAlgorithm(t *testing.T) {
	if _, err := NewWithCredential(Config{VaultURL: "https://vault.example.test", Credential: staticCredential("token"), Algorithm: "RS256"}); err == nil {
		t.Fatal("expected unsupported Azure signing algorithm to be rejected")
	}
}

func TestDecodeStrictJSONRejectsTrailingAndUnknownAzureResponseData(t *testing.T) {
	for _, body := range []string{`{"value":"ok","extra":true}`, `{"value":"ok"}{}`} {
		var response signResponse
		if err := decodeStrictJSON(strings.NewReader(body), &response); err == nil {
			t.Fatalf("body %q should be rejected", body)
		}
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

func azureKeyResponse(keyID string, privateKey *ecdsa.PrivateKey) keyResponse {
	return keyResponse{Key: struct {
		KeyID string `json:"kid"`
		KTY   string `json:"kty"`
		CRV   string `json:"crv"`
		X     string `json:"x"`
		Y     string `json:"y"`
	}{KeyID: keyID, KTY: "EC", CRV: "P-256", X: base64.RawURLEncoding.EncodeToString(paddedSignaturePart(privateKey.X)), Y: base64.RawURLEncoding.EncodeToString(paddedSignaturePart(privateKey.Y))}}
}

func paddedSignaturePart(value interface{ Bytes() []byte }) []byte {
	raw := value.Bytes()
	return append(make([]byte, 32-len(raw)), raw...)
}
