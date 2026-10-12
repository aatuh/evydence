package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"time"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Project only the public signature/lifecycle values selected by the existing
// SQL readiness reader. Key private bytes and bundle manifests are untouched.
func memoryReadinessSignedBundle(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, release string, at time.Time) (bool, error) {
	count, verified := 0, false
	for id, b := range s.ReleaseBundles {
		if b.ID != id || b.TenantID != tenant || b.ReleaseID != release {
			continue
		}
		for _, ref := range b.SignatureRefs {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			signature, ok := s.Signatures[ref]
			if !ok || signature.ID != ref || signature.TenantID != tenant || signature.SubjectType != "release_bundle" || signature.SubjectID != id || signature.Algorithm != "Ed25519" {
				continue
			}
			key, ok := s.SigningKeys[signature.KeyID]
			if !ok || key.ID != signature.KeyID || key.TenantID != tenant || key.Algorithm != "Ed25519" {
				continue
			}
			count++
			if count > 256 {
				return false, ErrValidation
			}
			for _, value := range []string{b.ManifestHash, signature.Value, key.PublicKey, key.Status, key.RevocationSemantics, key.HistoricalValidityPolicy} {
				if len(value) > 256 {
					return false, ErrValidation
				}
			}
			status, err := verificationdomain.ParseSigningKeyStatus(key.Status)
			if err != nil {
				continue
			}
			public := verificationdomain.SigningKey{Status: status, CreatedAt: key.CreatedAt, ValidFrom: key.ValidFrom, ValidUntil: key.ValidUntil, RevokedAt: key.RevokedAt, RevocationSemantics: key.RevocationSemantics, HistoricalValidityPolicy: key.HistoricalValidityPolicy, CompromisedAt: key.CompromisedAt}
			if public.HistoricalValidityAt(signature.CreatedAt, at) != verificationdomain.SigningKeyHistoricalValidityValid {
				continue
			}
			pub, pubErr := base64.RawStdEncoding.DecodeString(key.PublicKey)
			sig, sigErr := base64.RawStdEncoding.DecodeString(signature.Value)
			if pubErr == nil && sigErr == nil && len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(pub), []byte(b.ManifestHash), sig) {
				verified = true
			}
		}
	}
	return verified, nil
}
