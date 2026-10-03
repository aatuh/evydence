package app

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestHMACAuthenticationCredentialsMatchPersistedKeyFormat(t *testing.T) {
	credentials, err := NewHMACAuthenticationCredentials("test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "evy_secret"
	const hash = "e5f5dd5fee1b6f4a1b8d8c22190651443b9d871a4a35faf499141b81a45460cc"
	if got := credentials.Prefix(secret); got != secret {
		t.Fatalf("short prefix=%q", got)
	}
	if got := credentials.Prefix("evy_abcdefghijklmnopqrstuvwxyz"); got != "evy_abcdefgh" {
		t.Fatalf("long prefix=%q", got)
	}
	if got := credentials.Hash(secret); got != hash {
		t.Fatalf("hash mismatch")
	}
	if !credentials.Equal(hash, credentials.Hash(secret)) || credentials.Equal(hash, credentials.Hash("wrong-secret")) || credentials.Equal(hash, "short") {
		t.Fatal("hash comparison accepted an invalid credential")
	}
}

func TestHMACAuthenticationCredentialsGenerateCompatibleDistinctAPIKeys(t *testing.T) {
	c, err := NewHMACAuthenticationCredentials("test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.Generate()
	if err != nil {
		t.Fatal("credential generation failed")
	}
	b, err := c.Generate()
	if err != nil {
		t.Fatal("credential generation failed")
	}
	for _, v := range []Credential{a, b} {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v.Secret, "evy_"))
		if !strings.HasPrefix(v.Secret, "evy_") || err != nil || len(raw) != 32 || len(v.Prefix) != 12 || v.Prefix != c.Prefix(v.Secret) || len(v.Hash) != 64 || !c.Equal(v.Hash, c.Hash(v.Secret)) {
			t.Fatal("generated credential violates persisted format")
		}
	}
	if a.Secret == b.Secret || a.Hash == b.Hash {
		t.Fatal("credential generation repeated material")
	}
}

func TestHMACAuthenticationCredentialsRejectMissingPepper(t *testing.T) {
	if credentials, err := NewHMACAuthenticationCredentials(" "); !errors.Is(err, ErrValidation) || credentials != nil {
		t.Fatalf("unsafe credentials=%#v error=%v", credentials, err)
	}
}
