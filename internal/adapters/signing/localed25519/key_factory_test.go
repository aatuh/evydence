package localed25519

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestKeyFactoryProducesCompatibleEd25519Material(t *testing.T) {
	now := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	prepared, err := (KeyFactory{}).GenerateSigningKey(t.Context(), "tenant", verificationdomain.SigningKeyDefaultProvider, 2, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prepared.PrivateMaterial)
	public, err := base64.RawStdEncoding.Strict().DecodeString(prepared.Key.PublicKey)
	fingerprint := sha256.Sum256(public)
	if err != nil || len(public) != ed25519.PublicKeySize || len(prepared.PrivateMaterial) != ed25519.PrivateKeySize || prepared.Key.KID != "20261001T100000Z-v2" || prepared.Key.Version != 2 || prepared.Key.PublicKeyFingerprint != "sha256:"+hex.EncodeToString(fingerprint[:]) || prepared.Key.Status.String() != "active" || prepared.Key.HistoricalValidityPolicy != "preserve" || !prepared.Key.ValidFrom.Equal(now) {
		t.Fatalf("invalid public key metadata: %#v err=%v", prepared.Key, err)
	}
	value := ed25519.Sign(ed25519.PrivateKey(prepared.PrivateMaterial), []byte("hash"))
	if !ed25519.Verify(public, []byte("hash"), value) {
		t.Fatal("generated key pair does not verify")
	}
	for _, tc := range []struct {
		tenant, provider string
		version          int
		at               time.Time
	}{{"", "local_ed25519", 1, now}, {"tenant", "external", 1, now}, {"tenant", "local_ed25519", 0, now}, {"tenant", "local_ed25519", 2147483648, now}, {"tenant", "local_ed25519", 1, time.Time{}}} {
		if result, err := (KeyFactory{}).GenerateSigningKey(t.Context(), tc.tenant, tc.provider, tc.version, tc.at); !errors.Is(err, verificationapp.ErrValidation) || len(result.PrivateMaterial) != 0 {
			t.Fatal("invalid key generation input", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := (KeyFactory{}).GenerateSigningKey(ctx, "tenant", "local_ed25519", 1, now); !errors.Is(err, context.Canceled) || len(result.PrivateMaterial) != 0 {
		t.Fatal("canceled key generation", err)
	}
}
