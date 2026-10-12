package gcpkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/aatuh/evydence/internal/app"
)

func TestSignSendsDigestOnlyToGCPKMS(t *testing.T) {
	var gotAuth string
	var gotPath string
	var gotRequest signRequest
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(publicKeyResponse{Name: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), Algorithm: "EC_SIGN_P256_SHA256"})
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Fatal(err)
		}
		digest, err := base64.StdEncoding.DecodeString(gotRequest.Digest.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(signResponse{Signature: base64.StdEncoding.EncodeToString(signature), Name: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"})
	}))
	defer server.Close()

	executor, err := NewWithTokenSource(Config{Endpoint: server.URL, TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"}), Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Sign(t.Context(), app.SigningRequest{
		ProviderType:         "gcp_kms",
		KeyRef:               "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
		PayloadHash:          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CanonicalPayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer access-token" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if !strings.Contains(gotPath, "/v1/projects/p/") {
		t.Fatalf("path = %q", gotPath)
	}
	if gotRequest.Digest.SHA256 != base64.StdEncoding.EncodeToString(bytesOf(0xaa, 32)) {
		t.Fatalf("digest = %q", gotRequest.Digest.SHA256)
	}
	if result.Signature == "" || result.Algorithm != "gcp-kms:asymmetric-sign-sha256" || len(result.Checks) == 0 || result.Checks[0].Name != "gcp_kms_signature_verified" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSignRejectsSignatureThatDoesNotVerifyWithProviderPublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(publicKeyResponse{PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), Algorithm: "EC_SIGN_P256_SHA256"})
			return
		}
		_ = json.NewEncoder(w).Encode(signResponse{Signature: base64.StdEncoding.EncodeToString([]byte("not-a-signature"))})
	}))
	defer server.Close()
	executor, err := NewWithTokenSource(Config{Endpoint: server.URL, TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "access-token"}), Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.Sign(t.Context(), app.SigningRequest{ProviderType: "gcp_kms", KeyRef: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", CanonicalPayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err == nil {
		t.Fatal("expected a non-verifying provider signature to be rejected")
	}
}

func TestSignRejectsWrongProviderType(t *testing.T) {
	executor, err := NewWithTokenSource(Config{Endpoint: "https://kms.example.test", TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token"}), KeyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Sign(t.Context(), app.SigningRequest{ProviderType: "aws_kms", PayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
		t.Fatal("expected wrong provider type to be rejected")
	}
}

func TestNewWithTokenSourceRequiresHTTPSAndCredentials(t *testing.T) {
	if _, err := NewWithTokenSource(Config{Endpoint: "http://kms.example.test", TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token"})}); err == nil {
		t.Fatal("expected non-HTTPS endpoint to be rejected")
	}
	if _, err := NewWithTokenSource(Config{Endpoint: "https://kms.example.test"}); err == nil {
		t.Fatal("expected missing credential source to be rejected")
	}
}

func TestVerifySignatureSupportsGCPRSASigningProfiles(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("canonical signing request"))
	public := publicKeyResponse{PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))}
	for _, profile := range []struct {
		algorithm string
		sign      func() ([]byte, error)
	}{
		{algorithm: "RSA_SIGN_PSS_2048_SHA256", sign: func() ([]byte, error) { return rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:], nil) }},
		{algorithm: "RSA_SIGN_PKCS1_2048_SHA256", sign: func() ([]byte, error) { return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:]) }},
	} {
		t.Run(profile.algorithm, func(t *testing.T) {
			signature, err := profile.sign()
			if err != nil {
				t.Fatal(err)
			}
			public.Algorithm = profile.algorithm
			if err := verifySignature(public, digest[:], signature); err != nil {
				t.Fatalf("verify signature: %v", err)
			}
		})
	}
}

func TestVerifySignatureRejectsUnsupportedOrMalformedGCPPublicKey(t *testing.T) {
	digest := bytesOf(0xaa, 32)
	if err := verifySignature(publicKeyResponse{PEM: "not pem", Algorithm: "EC_SIGN_P256_SHA256"}, digest, []byte("signature")); err == nil {
		t.Fatal("expected malformed provider public key to be rejected")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(publicKeyResponse{PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), Algorithm: "EC_SIGN_P384_SHA384"}, digest, []byte("signature")); err == nil {
		t.Fatal("expected unsupported provider algorithm to be rejected")
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
			executor, err := NewWithTokenSource(Config{Endpoint: server.URL, TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token"}), Client: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			_, err = executor.fetchPublicKey(t.Context(), "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "token")
			if err == nil || strings.Contains(err.Error(), "provider payload") {
				t.Fatalf("err=%v, want safe provider failure", err)
			}
			if status >= 500 && !errors.Is(err, app.ErrRetryableSigning) {
				t.Fatalf("err=%v, want retryable failure", err)
			}
		})
	}
}

func TestSigningResponseHelpersRejectUnsafeValues(t *testing.T) {
	if _, err := decodePayloadHash("sha256:not-hex"); err == nil {
		t.Fatal("expected malformed digest to be rejected")
	}
	if validKeyName("projects/p/cryptoKeys/key") || validKeyName("projects/p/cryptoKeyVersions/../one") {
		t.Fatal("expected incomplete and traversal key names to be rejected")
	}
	response := &http.Response{Header: http.Header{"X-Goog-Request-Id": []string{strings.Repeat("a", 257)}}}
	if responseRequestID(response) != "" {
		t.Fatal("expected oversized request id to be discarded")
	}
	if firstNonEmpty("", "  chosen  ") != "chosen" {
		t.Fatal("expected first non-empty value")
	}
}

func TestSignClassifiesTransientGCPProviderFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	executor, err := NewWithTokenSource(Config{Endpoint: server.URL, TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token"}), Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.Sign(t.Context(), app.SigningRequest{ProviderType: "gcp_kms", KeyRef: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", CanonicalPayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if !errors.Is(err, app.ErrRetryableSigning) {
		t.Fatalf("err=%v, want retryable signing failure", err)
	}
}

func TestSignRejectsWrongGCPProviderBeforeNetworkCall(t *testing.T) {
	executor, err := NewWithTokenSource(Config{Endpoint: "https://kms.example.test", TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token"})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Sign(t.Context(), app.SigningRequest{ProviderType: "aws_kms", CanonicalPayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("err=%v, want validation", err)
	}
}

func TestDecodeStrictJSONRejectsTrailingAndUnknownGCPResponseData(t *testing.T) {
	for _, body := range []string{`{"signature":"ok","extra":true}`, `{"signature":"ok"}{}`} {
		var response signResponse
		if err := decodeStrictJSON(strings.NewReader(body), &response); err == nil {
			t.Fatalf("body %q should be rejected", body)
		}
	}
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}
