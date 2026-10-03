package app

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestSSOTrustMaterialRejectsPrivateMembers(t *testing.T) {
	for _, key := range []map[string]any{
		{"kty": "OKP", "kid": "fixture", "crv": "Ed25519", "x": "public-only"},
		{"kty": "RSA", "kid": "fixture", "n": "public-only", "e": "AQAB"},
	} {
		for _, field := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			for _, value := range []any{nil, "private-jwks-canary"} {
				private := make(map[string]any, len(key)+1)
				for k, v := range key {
					private[k] = v
				}
				private[field] = value
				if out, err := normalizeJWKS(map[string]any{"keys": []any{private}}); !errors.Is(err, ErrValidation) || out != nil {
					t.Fatal("private JOSE member accepted", key["kty"], field, err)
				}
			}
		}
	}
}

func TestSSOTrustMaterialCertificateNormalizationRetainsOnlyPublicCertificate(t *testing.T) {
	private, certificate := samlTestCertificate(t)
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	// The trailing block is deliberately not a certificate. Only the parsed
	// public certificate is normalized and retained, as in the existing policy.
	tail := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	input := []string{" \n" + certificate + tail + "\n "}
	public, err := normalizeSAMLSigningCertificates(input)
	if err != nil || len(public) != 1 || public[0] != certificate || strings.Contains(public[0], "PRIVATE KEY") {
		t.Fatal("certificate normalization contract changed", err)
	}
	input[0] = "mutated-input"
	if public[0] != certificate {
		t.Fatal("public certificate aliases caller slice")
	}
}

func TestSSOTrustMaterialPrivateImportCannotCreateRotateOrRefreshProvider(t *testing.T) {
	public := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "fixture", "crv": "Ed25519", "x": "public-only"}}}
	private := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "fixture", "crv": "Ed25519", "x": "public-only", "d": "private-jwks-canary"}}}
	discovery := &fakeOIDCDiscovery{result: OIDCDiscoveryResult{Issuer: "https://issuer.example.test", JWKS: private}}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, OIDC: discovery})
	_, _, _, actor := bootstrapEnterpriseTestTenant(t, ledger)
	counts := func() [2]int {
		ledger.mu.Lock()
		defer ledger.mu.Unlock()
		return [2]int{len(ledger.ssoProviders), len(ledger.chain[actor.TenantID])}
	}
	in := CreateSSOProviderInput{Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", JWKS: private}
	before := counts()
	if p, err := ledger.CreateSSOProvider(t.Context(), actor, in); !errors.Is(err, ErrValidation) || p.ID != "" || counts() != before {
		t.Fatal("private provider creation produced effects", err)
	}
	in.JWKS = public
	provider, err := ledger.CreateSSOProvider(t.Context(), actor, in)
	if err != nil || provider.ID == "" {
		t.Fatal("public provider creation rejected", err)
	}
	before = counts()
	badText := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "bad\x00", "crv": "Ed25519", "x": "public-only"}}}
	if p, err := ledger.UpdateSSOProviderTrustMaterial(t.Context(), actor, provider.ID, UpdateSSOProviderTrustMaterialInput{JWKS: badText}); !errors.Is(err, ErrValidation) || p.ID != "" || counts() != before {
		t.Fatal("NUL trust material produced effects", err)
	}
	if p, err := ledger.UpdateSSOProviderTrustMaterial(t.Context(), actor, provider.ID, UpdateSSOProviderTrustMaterialInput{JWKS: private}); !errors.Is(err, ErrValidation) || p.ID != "" || counts() != before {
		t.Fatal("private trust rotation produced effects", err)
	}
	if p, err := ledger.RefreshSSOProviderOIDCTrustMaterial(t.Context(), actor, provider.ID); !errors.Is(err, ErrVerificationFailed) || p.ID != "" || counts() != before {
		t.Fatal("private discovery response produced effects", err)
	}
	discovery.result.JWKS = badText
	if p, err := ledger.RefreshSSOProviderOIDCTrustMaterial(t.Context(), actor, provider.ID); !errors.Is(err, ErrVerificationFailed) || p.ID != "" || counts() != before {
		t.Fatal("NUL discovery text produced effects", err)
	}
	ledger.mu.Lock()
	stored := ledger.ssoProviders[provider.ID]
	ledger.mu.Unlock()
	if stored.TrustMaterialUpdatedAt != nil || !safePublicSSOFixture(t, stored) {
		t.Fatal("private import mutated original public trust")
	}
}

func safePublicSSOFixture(t *testing.T, provider domain.SSOProvider) bool {
	t.Helper()
	encoded, err := json.Marshal(provider)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(encoded), "public-only") && !strings.Contains(string(encoded), "private-jwks-canary")
}

func TestSSOProviderCreationRejectsUnsafePublicMetadata(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	_, _, _, actor := bootstrapEnterpriseTestTenant(t, ledger)
	base := CreateSSOProviderInput{Name: "Fixture", Type: "oidc", Issuer: "https://issuer.example.test/tenant", ClientID: "client"}
	counts := func() [2]int {
		ledger.mu.Lock()
		defer ledger.mu.Unlock()
		return [2]int{len(ledger.ssoProviders), len(ledger.chain[actor.TenantID])}
	}
	for _, bad := range []struct {
		name string
		set  func(*CreateSSOProviderInput)
	}{
		{"issuer credentials", func(in *CreateSSOProviderInput) {
			in.Issuer = "https://operator:private-issuer-canary@issuer.example.test"
		}},
		{"missing issuer host", func(in *CreateSSOProviderInput) { in.Issuer = "https:///path" }},
		{"issuer fragment", func(in *CreateSSOProviderInput) { in.Issuer += "#fragment" }},
		{"NUL name", func(in *CreateSSOProviderInput) { in.Name = "bad\x00" }},
		{"invalid UTF8 client", func(in *CreateSSOProviderInput) { in.ClientID = string([]byte{0xff}) }},
		{"NUL groups claim", func(in *CreateSSOProviderInput) { in.GroupsClaim = "bad\x00" }},
		{"NUL group mapping", func(in *CreateSSOProviderInput) { in.RoleMapping = map[string]string{"group": "bad\x00"} }},
	} {
		t.Run(bad.name, func(t *testing.T) {
			in := base
			bad.set(&in)
			before := counts()
			if out, err := ledger.CreateSSOProvider(t.Context(), actor, in); !errors.Is(err, ErrValidation) || out.ID != "" {
				t.Fatal("unsafe provider metadata accepted", err)
			}
			if counts() != before {
				t.Fatal("invalid provider metadata produced effects")
			}
		})
	}
}
