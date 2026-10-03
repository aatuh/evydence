package app

import (
	"errors"
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

func TestHMACAuthenticationCredentialsRejectMissingPepper(t *testing.T) {
	if credentials, err := NewHMACAuthenticationCredentials(" "); !errors.Is(err, ErrValidation) || credentials != nil {
		t.Fatalf("unsafe credentials=%#v error=%v", credentials, err)
	}
}
