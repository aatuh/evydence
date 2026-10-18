package sigstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

func TestLibraryVersionMatchesPinnedDependency(t *testing.T) {
	data, err := os.ReadFile("../../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	module, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, dependency := range module.Require {
		if dependency.Mod.Path == "github.com/sigstore/sigstore-go" {
			if LibraryVersion != "sigstore-go."+dependency.Mod.Version {
				t.Fatal("receipt library version does not match the pinned verifier")
			}
			return
		}
	}
	t.Fatal("Sigstore verifier dependency is absent")
}

func TestNewRejectsTrailingTrustMaterial(t *testing.T) {
	encoded, err := hex.DecodeString("04" +
		"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	key = append(key, []byte("PRIVATE_IGNORED_SUFFIX")...)
	if verifier, err := New(Config{TrustedPublicKeyPEM: key, TrustRootVersion: "fixture.v1"}); err == nil || verifier != nil {
		t.Fatal("constructor silently ignored trailing trust material")
	} else if strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("constructor disclosed invalid trust input")
	}
}
