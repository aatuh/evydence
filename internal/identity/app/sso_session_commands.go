package app

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SSOSessionWriteReader interface {
	LockSSOSessionWrites(context.Context, string) error
	ValidateSSOSessionTargets(context.Context, string, string, string) error
}
type SSOSessionTransaction interface {
	SSOSessionWriteReader
	application.Authorizer
	application.AuditAppender
	InsertSSOSession(context.Context, identitydomain.SSOSession) error
}
type SSOSessionTransactions interface {
	ExecuteSSOSession(context.Context, func(context.Context, SSOSessionTransaction) error) error
}
type SSOSessionCommandConfig struct {
	Transactions SSOSessionTransactions
	Credentials  SessionCredentialManager
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type SSOSessionCommands struct{ config SSOSessionCommandConfig }

func NewSSOSessionCommands(c SSOSessionCommandConfig) (*SSOSessionCommands, error) {
	if c.Transactions == nil || c.Credentials == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SSOSessionCommands{c}, nil
}
func normalizeSSOSessionInput(in CreateSSOSessionInput) (CreateSSOSessionInput, error) {
	if !validAPIKeyText(in.UserID, 1024) || !validAPIKeyText(in.ProviderID, 1024) || in.ExpiresAt.IsZero() || !validAPIKeyTime(in.ExpiresAt) {
		return in, ErrValidation
	}
	in.UserID, in.ProviderID = strings.TrimSpace(in.UserID), strings.TrimSpace(in.ProviderID)
	in.ExpiresAt = in.ExpiresAt.UTC().Truncate(time.Microsecond)
	if in.UserID == "" || in.ProviderID == "" || in.ExpiresAt.IsZero() || !validAPIKeyTime(in.ExpiresAt) {
		return in, ErrValidation
	}
	return in, nil
}
func (s *SSOSessionCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateSSOSessionInput) (CreateSSOSessionInput, error) {
	if s == nil || ctx == nil {
		return in, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return in, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, membershipAuthorization()); err != nil {
		return in, err
	}
	if !validAPIKeyID(a.TenantID) || !validAPIKeyID(actorID(a)) {
		return in, ErrValidation
	}
	return normalizeSSOSessionInput(in)
}
func (s *SSOSessionCommands) execute(ctx context.Context, a identitydomain.Actor, in CreateSSOSessionInput, run func(context.Context, SSOSessionTransaction) error) error {
	return s.config.Transactions.ExecuteSSOSession(ctx, func(ctx context.Context, tx SSOSessionTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, a, membershipAuthorization()); err != nil {
			return err
		}
		if err := tx.LockSSOSessionWrites(ctx, a.TenantID); err != nil {
			return err
		}
		if err := tx.ValidateSSOSessionTargets(ctx, a.TenantID, in.UserID, in.ProviderID); err != nil {
			return err
		}
		if err := run(ctx, tx); err != nil {
			return err
		}
		return ctx.Err()
	})
}

// Completed replay may outlive the original expiry, but it cannot reissue a
// credential. Check current administration authority and parents without minting.
func (s *SSOSessionCommands) AuthorizeCreateSSOSession(ctx context.Context, a identitydomain.Actor, in CreateSSOSessionInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, in, func(context.Context, SSOSessionTransaction) error { return nil })
}
func (s *SSOSessionCommands) CreateSSOSession(ctx context.Context, a identitydomain.Actor, in CreateSSOSessionInput) (identitydomain.SSOSession, string, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return identitydomain.SSOSession{}, "", err
	}
	var out identitydomain.SSOSession
	var secret string
	err = s.execute(ctx, a, in, func(ctx context.Context, tx SSOSessionTransaction) error {
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || !validAPIKeyTime(now) || !in.ExpiresAt.After(now) {
			return ErrValidation
		}
		credential, err := s.config.Credentials.GenerateSession()
		if err != nil {
			return err
		}
		if !validIssuedSessionCredential(credential) {
			return ErrValidation
		}
		out = identitydomain.SSOSession{ID: s.config.IDs.NewID("sess"), TenantID: a.TenantID, UserID: in.UserID, ProviderID: in.ProviderID, Prefix: credential.Prefix, Hash: credential.Hash, ExpiresAt: in.ExpiresAt, SchemaVersion: identitydomain.SSOSessionSchemaVersion, CreatedAt: now}
		if !validAPIKeyID(out.ID) {
			return ErrValidation
		}
		if err := tx.InsertSSOSession(ctx, out); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "sso_session.created", SubjectType: "human_user", SubjectID: in.UserID, ActorType: actorType(a), ActorID: actorID(a), OccurredAt: now}
		if !validAPIKeyID(audit.ID) {
			return ErrValidation
		}
		if _, err := tx.AppendAudit(ctx, audit); err != nil {
			return err
		}
		secret = credential.Secret
		return nil
	})
	if err != nil {
		return identitydomain.SSOSession{}, "", err
	}
	return publicSession(out), secret, nil
}
func validIssuedSessionCredential(c Credential) bool {
	if len(c.Secret) != 50 || !strings.HasPrefix(c.Secret, "evysso_") || len(c.Prefix) != 12 || c.Prefix != c.Secret[:12] || len(c.Hash) != 64 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Secret[7:])
	if err != nil || len(raw) != 32 {
		return false
	}
	hash, err := hex.DecodeString(c.Hash)
	return err == nil && len(hash) == 32
}
