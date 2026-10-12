package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Fixture signing stays in the current transaction. Existing private bytes
// never cross the port; a prepared initial/replacement key is owned by the
// command and cleared after atomic insertion. No external custody is modeled.
func (r memorySignatureRepository) SignMerkleRoot(ctx context.Context, request verificationapp.SigningRequest) (verificationapp.SigningResult, error) {
	if request.SubjectType != "merkle_batch" || request.SubjectID == "" || len(request.Payload) == 0 || len(request.Payload) > 1024 || request.CreatedAt.IsZero() {
		return verificationapp.SigningResult{}, ErrValidation
	}
	var out verificationapp.SigningResult
	err := memoryIdentityRepository(r).membershipRead(ctx, request.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		var selected domain.SigningKey
		var selectedID string
		maxVersion, localFound := 0, false
		for id, key := range s.SigningKeys {
			if err := ctx.Err(); err != nil {
				return err
			}
			if key.TenantID != request.TenantID || key.Provider != "" && key.Provider != verificationdomain.SigningKeyDefaultProvider {
				continue
			}
			if !localFound || key.Version > maxVersion {
				maxVersion = key.Version
			}
			localFound = true
			if key.Status != verificationdomain.SigningKeyStatusActive {
				continue
			}
			if selectedID == "" || key.Version > selected.Version || key.Version == selected.Version && key.ID < selected.ID {
				selectedID, selected = id, key
			}
		}
		var prepared *verificationapp.PreparedSigningKey
		if selectedID == "" {
			if maxVersion < 0 || maxVersion >= 2147483647 {
				return ErrConflict
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			status, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
			fingerprint := sha256.Sum256(public)
			at := request.CreatedAt.UTC()
			key := verificationdomain.SigningKey{ID: application.NewID("sk"), TenantID: request.TenantID, KID: fmt.Sprintf("%s-v%d", at.Format("20060102T150405Z"), maxVersion+1), Version: maxVersion + 1, Provider: verificationdomain.SigningKeyDefaultProvider, Algorithm: "Ed25519", Status: status, PublicKey: base64.RawStdEncoding.EncodeToString(public), PublicKeyFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]), ValidFrom: at, CreatedAt: at, HistoricalValidityPolicy: verificationdomain.SigningKeyHistoricalValidityPreserve}
			prepared = &verificationapp.PreparedSigningKey{Key: key, PrivateMaterial: private}
			selectedID = key.ID
			selected = domain.SigningKey{ID: key.ID, TenantID: key.TenantID, Algorithm: key.Algorithm, PublicKey: key.PublicKey, Private: private, ValidFrom: at}
		}
		success := false
		defer func() {
			if !success && prepared != nil {
				clear(prepared.PrivateMaterial)
			}
		}()
		if selected.ID != selectedID || !memoryGovernanceText(selected.ID, 1024) || selected.Algorithm != "Ed25519" || !memoryGovernanceText(selected.PublicKey, 128) || len(selected.Private) != ed25519.PrivateKeySize || selected.ValidFrom.After(request.CreatedAt) || selected.ValidUntil != nil && !request.CreatedAt.Before(*selected.ValidUntil) || selected.RevokedAt != nil || selected.CompromisedAt != nil {
			return ErrConflict
		}
		public, err := base64.RawStdEncoding.Strict().DecodeString(selected.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return ErrConflict
		}
		private := append([]byte(nil), selected.Private...)
		defer clear(private)
		derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
		defer clear(derived)
		if !ed25519.PrivateKey(private).Equal(derived) || !ed25519.PublicKey(private[ed25519.SeedSize:]).Equal(ed25519.PublicKey(public)) {
			return ErrConflict
		}
		value := ed25519.Sign(ed25519.PrivateKey(private), request.Payload)
		if err := ctx.Err(); err != nil {
			return err
		}
		out = verificationapp.SigningResult{Signature: verificationdomain.Signature{ID: application.NewID("sig"), TenantID: request.TenantID, SubjectType: request.SubjectType, SubjectID: request.SubjectID, KeyID: selected.ID, Algorithm: selected.Algorithm, Value: base64.RawStdEncoding.EncodeToString(value), CreatedAt: request.CreatedAt.UTC()}, NewKey: prepared}
		success = true
		return nil
	})
	if err != nil {
		if out.NewKey != nil {
			clear(out.NewKey.PrivateMaterial)
		}
		return verificationapp.SigningResult{}, err
	}
	return out, nil
}
