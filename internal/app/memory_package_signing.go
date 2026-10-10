package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

var _ packageapp.PackageSigner = memorySignatureRepository{}

// Test-backend local signing over current typed key rows, never Ledger. Only a
// public signature crosses this port; private bytes are copied and cleared.
// This model cannot establish PostgreSQL key locks or provider custody.
func (r memorySignatureRepository) SignPackage(ctx context.Context, request packageapp.PackageSigningRequest) (packageapp.PackageSignature, error) {
	var out packageapp.PackageSignature
	if request.SubjectID == "" || request.SubjectType == "" || request.PayloadHash == "" || request.CreatedAt.IsZero() {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, request.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		var selected domain.SigningKey
		var keyID string
		for id, key := range s.SigningKeys {
			if err := ctx.Err(); err != nil {
				return err
			}
			if key.TenantID != request.TenantID || key.Status != "active" {
				continue
			}
			if keyID == "" || key.Version > selected.Version || key.Version == selected.Version && key.ID < selected.ID {
				keyID, selected = id, key
			}
		}
		if keyID == "" || selected.ID != keyID || !memoryCurrentPackageSigningKey(selected, request.CreatedAt) || len(selected.Private) != ed25519.PrivateKeySize {
			return ErrConflict
		}
		public, err := base64.RawStdEncoding.Strict().DecodeString(selected.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return ErrConflict
		}
		private := append([]byte(nil), selected.Private...)
		defer clear(private)
		if !ed25519.PublicKey(private[ed25519.SeedSize:]).Equal(ed25519.PublicKey(public)) {
			return ErrConflict
		}
		value := ed25519.Sign(ed25519.PrivateKey(private), []byte(request.PayloadHash))
		if err := ctx.Err(); err != nil {
			return err
		}
		out = packageapp.PackageSignature{ID: application.NewID("sig"), TenantID: request.TenantID, SubjectType: request.SubjectType, SubjectID: request.SubjectID, KeyID: selected.ID, Algorithm: selected.Algorithm, Value: base64.RawStdEncoding.EncodeToString(value), CreatedAt: request.CreatedAt}
		return nil
	})
	if err != nil {
		return packageapp.PackageSignature{}, err
	}
	return out, nil
}

// Recheck current public lifecycle and the exact requested hash before the
// signature is inserted. No private key field is needed for this operation.
func (r memorySignatureRepository) ValidatePackageSignature(ctx context.Context, signature domain.Signature, hash string) error {
	if signature.KeyID == "" || signature.Algorithm != "Ed25519" || signature.CreatedAt.IsZero() || len(signature.Value) > 128 {
		return ErrConflict
	}
	return memoryIdentityRepository(r).membershipRead(ctx, signature.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		key, ok := s.SigningKeys[signature.KeyID]
		if !ok || key.ID != signature.KeyID || key.TenantID != signature.TenantID {
			return ErrNotFound
		}
		if !memoryCurrentPackageSigningKey(key, signature.CreatedAt) {
			return ErrConflict
		}
		public, err := base64.RawStdEncoding.Strict().DecodeString(key.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return ErrConflict
		}
		value, err := base64.RawStdEncoding.Strict().DecodeString(signature.Value)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(public), []byte(hash), value) {
			return ErrConflict
		}
		return ctx.Err()
	})
}

func memoryCurrentPackageSigningKey(key domain.SigningKey, at time.Time) bool {
	return memoryCustomerSnapshotID(key.ID, false) && key.Algorithm == "Ed25519" && key.Provider == "local_ed25519" && key.Status == "active" && !key.ValidFrom.After(at) && (key.ValidUntil == nil || at.Before(*key.ValidUntil)) && key.RevokedAt == nil && key.CompromisedAt == nil && memoryGovernanceText(key.PublicKey, 128)
}
