package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func (s *SigningKeyCommands) RotateSigningKey(ctx context.Context, actor identitydomain.Actor, reason string) (verificationdomain.SigningKey, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.SigningKey{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.SigningKey{}, err
	}
	if err := s.authorize(ctx, actor); err != nil {
		return verificationdomain.SigningKey{}, err
	}
	if !validSigningKeyText(reason) {
		return verificationdomain.SigningKey{}, ErrValidation
	}
	var rotated verificationdomain.SigningKey
	err := s.config.Transactions.ExecuteSigningKeyCommand(ctx, func(ctx context.Context, tx SigningKeyTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}); err != nil {
			return err
		}
		keys, err := tx.ListLocalSigningKeysForUpdate(ctx, actor.TenantID)
		if err != nil {
			return err
		}
		if len(keys) > MaxSigningRotationKeys {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC()
		version := 1
		retiring := make([]verificationdomain.SigningKey, 0)
		for _, key := range keys {
			if key.TenantID != actor.TenantID {
				return ErrNotFound
			}
			provider := strings.TrimSpace(key.Provider)
			if provider == "" {
				provider = verificationdomain.SigningKeyDefaultProvider
			}
			if provider != verificationdomain.SigningKeyDefaultProvider {
				continue
			}
			if key.Version >= 2147483647 {
				return ErrConflict
			}
			if key.Version < 1 && version < 2 {
				version = 2
			} else if key.Version >= version {
				version = key.Version + 1
			}
			if key.Status.String() == verificationdomain.SigningKeyStatusActive {
				status, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusRetiring)
				key.Status = status
				key.ValidUntil = timePointer(now)
				retiring = append(retiring, cloneSigningKey(key))
			}
		}
		generated, err := s.config.KeyFactory.GenerateSigningKey(ctx, actor.TenantID, verificationdomain.SigningKeyDefaultProvider, version, now)
		defer clear(generated.PrivateMaterial)
		if err != nil {
			return err
		}
		prepared := clonePreparedSigningKey(generated)
		defer clear(prepared.PrivateMaterial)
		if !validPreparedSigningKey(prepared, actor.TenantID, verificationdomain.SigningKeyDefaultProvider, version, now) {
			return ErrValidation
		}
		for _, prior := range retiring {
			if err := tx.UpdateSigningKey(ctx, prior, verificationdomain.SigningKeyStatusActive); err != nil {
				return err
			}
		}
		if err := tx.InsertSigningKey(ctx, prepared); err != nil {
			return err
		}
		audit := s.auditEvent(actor, now, "signing_key.rotated", prepared.Key.ID)
		if _, err := tx.AppendAudit(ctx, audit); err != nil {
			return err
		}
		rotated = cloneSigningKey(prepared.Key)
		return nil
	})
	if err != nil {
		return verificationdomain.SigningKey{}, err
	}
	return rotated, nil
}

func (s *SigningKeyCommands) RevokeSigningKey(ctx context.Context, actor identitydomain.Actor, keyID string, input SigningKeyRevocationInput) (verificationdomain.SigningKey, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.SigningKey{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.SigningKey{}, err
	}
	if err := s.authorize(ctx, actor); err != nil {
		return verificationdomain.SigningKey{}, err
	}
	keyID = strings.TrimSpace(keyID)
	input, err := normalizeRevocationInput(input)
	if !validSigningKeyText(keyID) || err != nil {
		return verificationdomain.SigningKey{}, ErrValidation
	}
	var revoked verificationdomain.SigningKey
	err = s.config.Transactions.ExecuteSigningKeyCommand(ctx, func(ctx context.Context, tx SigningKeyTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}); err != nil {
			return err
		}
		key, err := tx.GetSigningKeyForUpdate(ctx, actor.TenantID, keyID)
		if err != nil {
			return err
		}
		if key.ID != keyID || key.TenantID != actor.TenantID {
			return ErrNotFound
		}
		previous := key.Status.String()
		if previous == verificationdomain.SigningKeyStatusRevoked {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC()
		status, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusRevoked)
		key.Status = status
		key.RevokedAt = timePointer(now)
		key.ValidUntil = timePointer(now)
		key.RevocationReason, key.RevocationSemantics, key.HistoricalValidityPolicy = input.Reason, input.Semantics, input.HistoricalValidityPolicy
		if input.Semantics == verificationdomain.SigningKeyRevocationCompromised {
			key.CompromisedAt = timePointer(now)
		}
		if err := tx.UpdateSigningKey(ctx, key, previous); err != nil {
			return err
		}
		action := "signing_key.revoked"
		if input.Semantics == verificationdomain.SigningKeyRevocationCompromised {
			action = "signing_key.compromised"
		}
		audit := s.auditEvent(actor, now, action, key.ID)
		if _, err := tx.AppendAudit(ctx, audit); err != nil {
			return err
		}
		revoked = cloneSigningKey(key)
		return nil
	})
	if err != nil {
		return verificationdomain.SigningKey{}, err
	}
	return revoked, nil
}

// Key identifiers and operator reasons must be valid database text, not
// binary strings that become persistence failures after authorization.
func validSigningKeyText(value string) bool {
	return strings.TrimSpace(value) != "" && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}
