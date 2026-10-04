package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// SigningKeyScopeLocker is an optional native transaction extension. Replay
// needs current ownership, not lifecycle metadata or private signing material.
type SigningKeyScopeLocker interface {
	LockSigningKeyScope(context.Context, string, string) error
}

func NormalizeSigningKeyReason(raw string) (string, error) {
	if len(raw) > 4096 || !validSigningKeyText(raw) {
		return "", ErrValidation
	}
	return strings.TrimSpace(raw), nil
}

func NormalizeSigningKeyID(raw string) (string, error) {
	if len(raw) > 1024 || !validSigningKeyText(raw) {
		return "", ErrValidation
	}
	return strings.TrimSpace(raw), nil
}

func validateSigningKeyActor(actor identitydomain.Actor) error {
	if err := validateActor(actor); err != nil {
		return err
	}
	if len(actor.TenantID) > 1024 || !validSigningKeyText(actor.TenantID) || strings.TrimSpace(actor.TenantID) != actor.TenantID {
		return ErrValidation
	}
	return nil
}

func (s *SigningKeyCommands) AuthorizeSigningKeyRotation(ctx context.Context, actor identitydomain.Actor) error {
	return s.authorizeSigningKeyReplay(ctx, actor, "")
}

func (s *SigningKeyCommands) AuthorizeSigningKeyRevocation(ctx context.Context, actor identitydomain.Actor, raw string) error {
	id, err := NormalizeSigningKeyID(raw)
	if err != nil {
		return err
	}
	return s.authorizeSigningKeyReplay(ctx, actor, id)
}

func (s *SigningKeyCommands) authorizeSigningKeyReplay(ctx context.Context, actor identitydomain.Actor, id string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateSigningKeyActor(actor); err != nil {
		return err
	}
	if err := s.authorize(ctx, actor); err != nil {
		return err
	}
	return s.config.Transactions.ExecuteSigningKeyCommand(ctx, func(ctx context.Context, tx SigningKeyTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}); err != nil {
			return err
		}
		if id == "" {
			return nil
		}
		locker, ok := tx.(SigningKeyScopeLocker)
		if !ok {
			return ErrValidation
		}
		return locker.LockSigningKeyScope(ctx, actor.TenantID, id)
	})
}
