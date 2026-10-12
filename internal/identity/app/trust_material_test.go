package app

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestPublicTrustMaterialValidatorCopiesPublicKeysAndRejectsPrivateMembers(t *testing.T) {
	validator := PublicTrustMaterialValidator{}
	keys := []any{map[string]any{"kty": "RSA", "kid": "fixture", "n": "public-only", "e": "AQAB", "use": "sig", "key_ops": []any{"verify"}}}
	in := map[string]any{"keys": keys}
	public, err := validator.NormalizeJWKS(in)
	if err != nil || !reflect.DeepEqual(public, in) {
		t.Fatal("public JWKS contract changed", err)
	}
	keys[0].(map[string]any)["n"] = "mutated-input"
	keys[0].(map[string]any)["key_ops"].([]any)[0] = "mutated-input"
	stored := public["keys"].([]any)[0].(map[string]any)
	if stored["n"] != "public-only" || stored["key_ops"].([]any)[0] != "verify" {
		t.Fatal("normalized JWKS aliases input")
	}
	for _, field := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		for _, where := range []string{"root", "key"} {
			input := cloneAnyMap(public)
			if where == "root" {
				input[field] = nil
			} else {
				input["keys"].([]any)[0].(map[string]any)[field] = []any{"private-jwks-canary"}
			}
			if out, err := validator.NormalizeJWKS(input); !errors.Is(err, ErrValidation) || out != nil {
				t.Fatal("private member survived normalization", field, where, err)
			}
		}
	}
	for _, bad := range []map[string]any{
		{"keys": []any{}}, {"keys": nil}, {"keys": []any{nil}},
		{"keys": []any{map[string]any{"kty": "RSA", "n": "n", "e": "e"}}},
		{"keys": []any{map[string]any{"kty": "oct", "kid": "fixture", "k": "private"}}},
		{"keys": []any{map[string]any{"kty": "OKP", "kid": "fixture", "crv": "other", "x": "x"}}},
		{"keys": []any{map[string]any{"kty": "RSA", "kid": "fixture", "n": "n", "e": ""}}},
		{"keys": []any{map[string]any{"kty": "OKP", "kid": "fixture", "crv": "Ed25519", "x": ""}}},
		{"keys": []any{map[string]any{"kty": "RSA", "kid": "fixture", "n": strings.Repeat("n", 65536), "e": "e"}}},
		{"keys": make([]any, 11)}, {"keys": []any{make(chan int)}},
	} {
		if out, err := validator.NormalizeJWKS(bad); !errors.Is(err, ErrValidation) || out != nil {
			t.Fatal("malformed trust material accepted", err)
		}
	}
	if out, err := validator.NormalizeJWKS(nil); err != nil || out != nil {
		t.Fatal("optional empty trust material changed", err)
	}
	for _, bad := range [][]string{{""}, {"not-pem"}, {strings.Repeat("x", 16385)}, make([]string, 6)} {
		if out, err := validator.NormalizeSAMLSigningCertificates(bad); !errors.Is(err, ErrValidation) || out != nil {
			t.Fatal("malformed certificates accepted", err)
		}
	}
	if out, err := validator.NormalizeSAMLSigningCertificates(nil); err != nil || out != nil {
		t.Fatal("optional empty certificates changed", err)
	}
}

func TestPublicTrustMaterialValidatorDoesNotRetainUnrecognizedMetadata(t *testing.T) {
	in := map[string]any{
		"client_secret": "private-jwks-canary",
		"extension":     map[string]any{"password": "private-jwks-canary"},
		"keys": []any{map[string]any{
			"kty": "RSA", "kid": "fixture", "n": "public-only", "e": "AQAB",
			"alg": "RS256", "use": "sig", "key_ops": []any{"verify"},
			"x5c":           []any{"public-certificate"},
			"client_secret": "private-jwks-canary",
			"extension":     map[string]any{"password": "private-jwks-canary"},
		}},
	}
	public, err := (PublicTrustMaterialValidator{}).NormalizeJWKS(in)
	if err != nil {
		t.Fatal("public projection rejected supported fields", err)
	}
	encoded, err := json.Marshal(public)
	if err != nil || strings.Contains(string(encoded), "private-jwks-canary") || strings.Contains(string(encoded), "client_secret") || strings.Contains(string(encoded), "extension") {
		t.Fatal("unrecognized trust metadata reached public projection", err)
	}
	key := public["keys"].([]any)[0].(map[string]any)
	if key["alg"] != "RS256" || key["use"] != "sig" || key["key_ops"].([]any)[0] != "verify" || key["x5c"].([]any)[0] != "public-certificate" {
		t.Fatal("supported public JWK metadata lost")
	}
	for _, field := range []string{"alg", "use", "x5u", "x5t", "x5t#S256", "key_ops", "x5c"} {
		malformed := cloneAnyMap(public)
		malformed["keys"].([]any)[0].(map[string]any)[field] = map[string]any{"password": "private-jwks-canary"}
		if out, err := (PublicTrustMaterialValidator{}).NormalizeJWKS(malformed); !errors.Is(err, ErrValidation) || out != nil {
			t.Fatal("malformed public member retained nested metadata", field, err)
		}
	}
}
