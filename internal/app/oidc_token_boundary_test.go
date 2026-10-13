package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type oidcBoundaryFixture struct {
	provider             domain.SSOProvider
	header               map[string]any
	claims               map[string]any
	key                  map[string]any
	private              ed25519.PrivateKey
	now                  time.Time
	rawHeader, rawClaims string
}

func newOIDCBoundaryFixture() oidcBoundaryFixture {
	seed := sha256.Sum256([]byte("evydence signed OIDC boundary fixture"))
	private := ed25519.NewKeyFromSeed(seed[:])
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	key := map[string]any{"kid": "fixture-key", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}
	return oidcBoundaryFixture{
		provider: domain.SSOProvider{ID: "provider", TenantID: "tenant", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", JWKS: map[string]any{"keys": []any{key}}},
		header:   map[string]any{"alg": "EdDSA", "kid": "fixture-key", "typ": "JWT"},
		claims:   map[string]any{"iss": "https://issuer.example.test", "sub": "subject", "aud": "client", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": "signed-fixture-nonce"},
		key:      key, private: private, now: now,
	}
}

func (f oidcBoundaryFixture) token(t *testing.T) string {
	t.Helper()
	header, err := json.Marshal(f.header)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(f.claims)
	if err != nil {
		t.Fatal(err)
	}
	if f.rawHeader != "" {
		header = []byte(f.rawHeader)
	}
	if f.rawClaims != "" {
		claims = []byte(f.rawClaims)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.private, []byte(unsigned)))
}

func TestOIDCIDTokenRejectsAmbiguousOrUnboundSignedProof(t *testing.T) {
	cases := []struct {
		name   string
		change func(*oidcBoundaryFixture)
	}{
		{"wrong issuer", func(f *oidcBoundaryFixture) { f.claims["iss"] = "https://other.example.test" }},
		{"wrong subject", func(f *oidcBoundaryFixture) { f.claims["sub"] = "other" }},
		{"wrong audience", func(f *oidcBoundaryFixture) { f.claims["aud"] = "other" }},
		{"untrusted additional audience", func(f *oidcBoundaryFixture) { f.claims["aud"] = []any{"client", "other"}; f.claims["azp"] = "client" }},
		{"mixed audience types", func(f *oidcBoundaryFixture) { f.claims["aud"] = []any{"client", 7} }},
		{"duplicate audience", func(f *oidcBoundaryFixture) { f.claims["aud"] = []any{"client", "client"} }},
		{"wrong authorized party", func(f *oidcBoundaryFixture) { f.claims["azp"] = "other" }},
		{"null authorized party", func(f *oidcBoundaryFixture) { f.claims["azp"] = nil }},
		{"missing issued time", func(f *oidcBoundaryFixture) { delete(f.claims, "iat") }},
		{"future issued time", func(f *oidcBoundaryFixture) { f.claims["iat"] = f.now.Add(2 * time.Minute).Unix() }},
		{"issued after expiry", func(f *oidcBoundaryFixture) { f.claims["iat"] = f.now.Add(2 * time.Hour).Unix() }},
		{"negative issued time", func(f *oidcBoundaryFixture) { f.claims["iat"] = -1 }},
		{"expired", func(f *oidcBoundaryFixture) { f.claims["exp"] = f.now.Unix() }},
		{"duplicate header member", func(f *oidcBoundaryFixture) { f.rawHeader = `{"alg":"RS256","alg":"EdDSA","kid":"fixture-key"}` }},
		{"duplicate signed claim", func(f *oidcBoundaryFixture) {
			b, _ := json.Marshal(f.claims)
			f.rawClaims = strings.Replace(string(b), `"sub":"subject"`, `"sub":"other","sub":"subject"`, 1)
		}},
		{"unsupported critical header", func(f *oidcBoundaryFixture) { f.header["crit"] = []any{"b64"}; f.header["b64"] = false }},
		{"access token type", func(f *oidcBoundaryFixture) { f.header["typ"] = "at+jwt" }},
		{"null token type", func(f *oidcBoundaryFixture) { f.header["typ"] = nil }},
		{"encryption key use", func(f *oidcBoundaryFixture) { f.key["use"] = "enc" }},
		{"conflicting key algorithm", func(f *oidcBoundaryFixture) { f.key["alg"] = "RS256" }},
		{"nonverification key operations", func(f *oidcBoundaryFixture) { f.key["key_ops"] = []any{"encrypt"} }},
		{"malformed key operations", func(f *oidcBoundaryFixture) { f.key["key_ops"] = "verify" }},
		{"ambiguous key id", func(f *oidcBoundaryFixture) { f.provider.JWKS["keys"] = []any{f.key, f.key} }},
		{"private key material", func(f *oidcBoundaryFixture) { f.key["d"] = "private-fixture-marker" }},
		{"empty configured client", func(f *oidcBoundaryFixture) { f.provider.ClientID = ""; f.claims["aud"] = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOIDCBoundaryFixture()
			tc.change(&f)
			if _, err := verifyOIDCIDToken(f.provider, "subject", f.token(t), f.now); err == nil {
				t.Fatal("unsafe signed OIDC proof was accepted")
			}
		})
	}
}

func TestOIDCIDTokenAcceptsExplicitClientAndUnambiguousPublicVerificationKey(t *testing.T) {
	for _, profile := range []string{"standard", "single audience array", "unspecified key usage", "rotated distinct key", "lowercase token type"} {
		t.Run(profile, func(t *testing.T) {
			f := newOIDCBoundaryFixture()
			switch profile {
			case "single audience array":
				f.claims["aud"] = []any{"client"}
				f.claims["azp"] = "client"
				f.key["key_ops"] = []any{"verify"}
			case "unspecified key usage":
				delete(f.key, "use")
				delete(f.key, "alg")
			case "rotated distinct key":
				other := map[string]any{"kid": "other-key", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": f.key["x"]}
				f.provider.JWKS["keys"] = []any{other, f.key}
			case "lowercase token type":
				f.header["typ"] = "jwt"
			}
			if _, err := verifyOIDCIDToken(f.provider, "subject", f.token(t), f.now); err != nil {
				t.Fatal("supported OIDC proof was rejected", err)
			}
		})
	}
}

func TestOIDCRSAPublicTrustRejectsWeakUnboundedOrInvalidParameters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bits     uint
		exponent []byte
		good     bool
	}{
		{"supported", 2048, []byte{1, 0, 1}, true},
		{"weak modulus", 1024, []byte{1, 0, 1}, false},
		{"oversized modulus", 8193, []byte{1, 0, 1}, false},
		{"even exponent", 2048, []byte{4}, false},
		{"oversized exponent", 2048, []byte{128, 0, 0, 1}, false},
		{"nonminimal exponent", 2048, []byte{0, 1, 0, 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := new(big.Int).Lsh(big.NewInt(1), tc.bits-1)
			n.Add(n, big.NewInt(1))
			key := map[string]any{"kid": "rsa", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(n.Bytes()), "e": base64.RawURLEncoding.EncodeToString(tc.exponent)}
			_, err := oidcJWKRSAKey(map[string]any{"keys": []any{key}}, "rsa")
			if (err == nil) != tc.good {
				t.Fatal("RSA verification-key policy mismatch", err)
			}
		})
	}
}
