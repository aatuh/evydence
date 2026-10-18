package config

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func publicTrustKeyFixture(t *testing.T) []byte {
	t.Helper()
	// The same public P-256 generator point as the previous coordinate fixture.
	encoded, err := hex.DecodeString("04" +
		"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func trustedRootFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../adapters/verification/sigstore/testdata/official-scaffolding.trusted-root.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSigstoreTrustParsingIsOwnedRedactedAndOffline(t *testing.T) {
	for _, tc := range []struct{ root, key []byte }{
		{root: trustedRootFixture(t)},
		{key: publicTrustKeyFixture(t)},
		{root: trustedRootFixture(t), key: publicTrustKeyFixture(t)},
	} {
		trust, err := ParseSigstoreTrustMaterial(tc.root, tc.key, "PRIVATE_VERSION")
		if err != nil || trust.Material() == nil || trust.Version() != "PRIVATE_VERSION" {
			t.Fatal("trust parsing rejected valid public material or attempted resolution", err)
		}
		for _, value := range []any{trust, &trust, struct{ Trust SigstoreTrustMaterial }{trust}} {
			if strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
				t.Fatal("trust formatting exposed operator material")
			}
			encoded, err := json.Marshal(value)
			if err != nil || strings.Contains(string(encoded), "PRIVATE") {
				t.Fatal("trust JSON exposed operator material", err)
			}
		}
		// Mutating supplied material must not affect the parsed trust object.
		before := trustSnapshot(t, trust, len(tc.key) != 0)
		clear(tc.root)
		clear(tc.key)
		if !bytes.Equal(before, trustSnapshot(t, trust, len(tc.key) != 0)) || trust.Version() != "PRIVATE_VERSION" {
			t.Fatal("caller mutation changed owned trust")
		}
	}
}

func trustSnapshot(t *testing.T, trust SigstoreTrustMaterial, hasKey bool) []byte {
	t.Helper()
	m := trust.Material()
	values := []any{m.RekorLogs(), m.CTLogs(), m.FulcioCertificateAuthorities(), m.TimestampingAuthorities()}
	if hasKey {
		verifier, err := m.PublicKeyVerifier("fixture")
		if err != nil {
			t.Fatal(err)
		}
		key, err := verifier.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, der)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestSigstoreTrustRejectsMalformedOrMixedMaterialSafely(t *testing.T) {
	public := publicTrustKeyFixture(t)
	block, _ := pem.Decode(public)
	wrongLabel := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: block.Bytes})
	unsupported, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	unsupportedDER, err := x509.MarshalPKIXPublicKey(unsupported)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		root, key []byte
		version   string
	}{
		{version: "PRIVATE_VERSION"},
		{key: public},
		{key: public, version: "PRIVATE_VERSION\nInjected"},
		{key: public, version: strings.Repeat("x", 257)},
		{root: []byte(`{"mediaType":"PRIVATE_INVALID"}`), version: "PRIVATE_VERSION"},
		{root: []byte(`{"PRIVATE_UNKNOWN":true}`), version: "PRIVATE_VERSION"},
		{root: []byte(`{}`), version: "PRIVATE_VERSION"},
		{root: make([]byte, (1<<20)+1), version: "PRIVATE_VERSION"},
		{key: []byte("PRIVATE_NOT_PEM"), version: "PRIVATE_VERSION"},
		{key: wrongLabel, version: "PRIVATE_VERSION"},
		{key: append([]byte("PRIVATE_PREFIX\n"), public...), version: "PRIVATE_VERSION"},
		{key: append(append([]byte{}, public...), []byte("PRIVATE_SUFFIX")...), version: "PRIVATE_VERSION"},
		{key: append(append([]byte{}, public...), public...), version: "PRIVATE_VERSION"},
		{key: append([]byte("-----BEGIN PUBLIC KEY-----\nPRIVATE_INVALID\n-----END PUBLIC KEY-----\n"), public...), version: "PRIVATE_VERSION"},
		{key: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"PRIVATE_HEADER": "value"}, Bytes: block.Bytes}), version: "PRIVATE_VERSION"},
		{key: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: unsupportedDER}), version: "PRIVATE_VERSION"},
	} {
		trust, err := ParseSigstoreTrustMaterial(tc.root, tc.key, tc.version)
		if err == nil || !reflect.DeepEqual(trust, SigstoreTrustMaterial{}) || (!errors.Is(err, ErrInvalidValue) && !errors.Is(err, ErrMissingValue)) {
			t.Fatal("invalid trust configuration returned partial material or an unsafe cause", err)
		}
		if strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("trust parser exposed supplied input or a library cause")
		}
	}
}

func TestRoleInputValidatesSigstoreTrustBeforeConstruction(t *testing.T) {
	for _, extra := range [][]string{
		{"EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64=e30=", "EVYDENCE_SIGSTORE_TRUST_ROOT_VERSION=PRIVATE_VERSION"},
		{"EVYDENCE_SIGSTORE_TRUSTED_PUBLIC_KEY_PEM_BASE64=" + base64.StdEncoding.EncodeToString(publicTrustKeyFixture(t))},
		{"EVYDENCE_SIGSTORE_TRUST_ROOT_VERSION=PRIVATE_VERSION\nInjected"},
	} {
		input, err := parseRoleInput(roleEnvironment(t, API, false, extra...), API)
		if err == nil || !reflect.DeepEqual(input, parsedInput{}) {
			t.Fatal("runtime accepted incomplete or malformed trust settings")
		}
	}
	if _, err := parseRoleInput(roleEnvironment(t, API, false,
		"EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64="+base64.StdEncoding.EncodeToString(trustedRootFixture(t)),
		"EVYDENCE_SIGSTORE_TRUST_ROOT_VERSION=fixture.v1",
	), API); err != nil {
		t.Fatal("runtime rejected valid offline trust input", err)
	}
}
