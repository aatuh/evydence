package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SSOSessionRevocationReader interface {
	LockSSOSessionWrites(context.Context, string) error
	ReadSSOSessionForRevocation(context.Context, string, string) (identitydomain.SSOSession, error)
}
type SSOSessionRevocationTransaction interface {
	SSOSessionRevocationReader
	application.Authorizer
	application.AuditAppender
	RevokeSSOSessionMetadata(context.Context, identitydomain.SSOSession, time.Time) error
}
type SSOSessionRevocationTransactions interface {
	ExecuteSSOSessionRevocation(context.Context, func(context.Context, SSOSessionRevocationTransaction) error) error
}
type SSOSessionRevocationConfig struct {
	Transactions SSOSessionRevocationTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type SSOSessionRevocationCommands struct{ config SSOSessionRevocationConfig }

func NewSSOSessionRevocationCommands(c SSOSessionRevocationConfig) (*SSOSessionRevocationCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SSOSessionRevocationCommands{c}, nil
}

const sessionLogoutScope = "identity:logout"

type sessionRevocationAuthorizer struct{}

func NewSSOSessionRevocationAuthorizer() application.Authorizer { return sessionRevocationAuthorizer{} }
func (sessionRevocationAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r == membershipAuthorization() {
		return NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
	}
	if r != (application.AuthorizationRequest{Scope: sessionLogoutScope}) {
		return application.ErrForbidden
	}
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(a.UserID) == "" || strings.TrimSpace(a.SessionID) == "" || a.KeyID != "" || a.CollectorID != "" {
		return application.ErrForbidden
	}
	return nil
}
func revocationAuthorization(self bool) application.AuthorizationRequest {
	if self {
		return application.AuthorizationRequest{Scope: sessionLogoutScope}
	}
	return membershipAuthorization()
}
func normalizeRevocationID(id string) (string, error) {
	if !validAPIKeyText(id, 1024) {
		return "", ErrValidation
	}
	id = strings.TrimSpace(id)
	if !validAPIKeyID(id) {
		return "", ErrValidation
	}
	return id, nil
}
func (s *SSOSessionRevocationCommands) prepare(ctx context.Context, a identitydomain.Actor, id string, self bool) (string, error) {
	if s == nil || ctx == nil {
		return "", ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, revocationAuthorization(self)); err != nil {
		return "", err
	}
	if !validAPIKeyID(a.TenantID) || !validAPIKeyID(actorID(a)) || self && !validAPIKeyID(a.SessionID) {
		return "", ErrValidation
	}
	return normalizeRevocationID(id)
}
func validRevocationMetadata(v identitydomain.SSOSession) bool {
	return validAPIKeyID(v.ID) && validAPIKeyID(v.TenantID) && validAPIKeyID(v.UserID) && validAPIKeyID(v.ProviderID) && validAPIKeyID(v.Prefix) && validAPIKeyID(v.SchemaVersion) && v.Hash == "" && !v.CreatedAt.IsZero() && validAPIKeyTime(v.CreatedAt) && !v.ExpiresAt.IsZero() && validAPIKeyTime(v.ExpiresAt) && (v.RevokedAt == nil || !v.RevokedAt.IsZero() && validAPIKeyTime(*v.RevokedAt))
}
func (s *SSOSessionRevocationCommands) execute(ctx context.Context, a identitydomain.Actor, id string, self bool, fn func(context.Context, SSOSessionRevocationTransaction, identitydomain.SSOSession) error) error {
	return s.config.Transactions.ExecuteSSOSessionRevocation(ctx, func(ctx context.Context, tx SSOSessionRevocationTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, a, revocationAuthorization(self)); err != nil {
			return err
		}
		if err := tx.LockSSOSessionWrites(ctx, a.TenantID); err != nil {
			return err
		}
		v, err := tx.ReadSSOSessionForRevocation(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if v.ID != id || v.TenantID != a.TenantID || self && (v.UserID != a.UserID || v.ID != a.SessionID) {
			return ErrNotFound
		}
		if !validRevocationMetadata(v) {
			return ErrConflict
		}
		if err := fn(ctx, tx, cloneSSOSession(v)); err != nil {
			return err
		}
		return ctx.Err()
	})
}

// Replay checks current authority and session ownership, not the pre-revocation
// state: a successful revocation is still eligible for metadata-only replay.
func (s *SSOSessionRevocationCommands) authorize(ctx context.Context, a identitydomain.Actor, id string, self bool) error {
	id, err := s.prepare(ctx, a, id, self)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, id, self, func(context.Context, SSOSessionRevocationTransaction, identitydomain.SSOSession) error { return nil })
}
func (s *SSOSessionRevocationCommands) AuthorizeRevokeSSOSession(ctx context.Context, a identitydomain.Actor, id string) error {
	return s.authorize(ctx, a, id, false)
}
func (s *SSOSessionRevocationCommands) AuthorizeRevokeCurrentSSOSession(ctx context.Context, a identitydomain.Actor) error {
	return s.authorize(ctx, a, a.SessionID, true)
}
func (s *SSOSessionRevocationCommands) RevokeSSOSession(ctx context.Context, a identitydomain.Actor, id string) (identitydomain.SSOSession, error) {
	return s.revoke(ctx, a, id, false)
}
func (s *SSOSessionRevocationCommands) RevokeCurrentSSOSession(ctx context.Context, a identitydomain.Actor) (identitydomain.SSOSession, error) {
	return s.revoke(ctx, a, a.SessionID, true)
}
func (s *SSOSessionRevocationCommands) revoke(ctx context.Context, a identitydomain.Actor, id string, self bool) (identitydomain.SSOSession, error) {
	id, err := s.prepare(ctx, a, id, self)
	if err != nil {
		return identitydomain.SSOSession{}, err
	}
	var out identitydomain.SSOSession
	err = s.execute(ctx, a, id, self, func(ctx context.Context, tx SSOSessionRevocationTransaction, v identitydomain.SSOSession) error {
		if v.RevokedAt != nil {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || !validAPIKeyTime(now) {
			return ErrValidation
		}
		if err := tx.RevokeSSOSessionMetadata(ctx, v, now); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "sso_session.revoked", SubjectType: "sso_session", SubjectID: v.ID, ActorType: actorType(a), ActorID: actorID(a), OccurredAt: now}
		if !validAPIKeyID(audit.ID) {
			return ErrValidation
		}
		if _, err := tx.AppendAudit(ctx, audit); err != nil {
			return err
		}
		v.RevokedAt = &now
		out = publicSession(v)
		return nil
	})
	if err != nil {
		return identitydomain.SSOSession{}, err
	}
	return out, nil
}
