// Package localed25519 implements the existing local Ed25519 key format.
// It does not provide external key custody or encryption at rest.
package localed25519

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type KeyFactory struct{}

var _ verificationapp.KeyFactory = KeyFactory{}

func (KeyFactory) GenerateSigningKey(ctx context.Context, tenantID, provider string, version int, now time.Time) (verificationapp.PreparedSigningKey, error) {
	if ctx == nil {
		return verificationapp.PreparedSigningKey{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return verificationapp.PreparedSigningKey{}, err
	}
	if strings.TrimSpace(tenantID) == "" || provider != verificationdomain.SigningKeyDefaultProvider || version < 1 || version > 2147483647 || now.IsZero() {
		return verificationapp.PreparedSigningKey{}, verificationapp.ErrValidation
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return verificationapp.PreparedSigningKey{}, err
	}
	if err := ctx.Err(); err != nil {
		clear(private)
		return verificationapp.PreparedSigningKey{}, err
	}
	fingerprint := sha256.Sum256(public)
	status, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
	now = now.UTC()
	return verificationapp.PreparedSigningKey{Key: verificationdomain.SigningKey{ID: application.NewID("sk"), TenantID: tenantID, KID: fmt.Sprintf("%s-v%d", now.Format("20060102T150405Z"), version), Version: version, Provider: provider, Algorithm: "Ed25519", Status: status, PublicKey: base64.RawStdEncoding.EncodeToString(public), PublicKeyFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]), ValidFrom: now, CreatedAt: now, HistoricalValidityPolicy: verificationdomain.SigningKeyHistoricalValidityPreserve}, PrivateMaterial: private}, nil
}
