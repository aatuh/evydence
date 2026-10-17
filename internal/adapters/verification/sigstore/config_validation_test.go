package sigstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
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
	curve := elliptic.P256()
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy})
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
