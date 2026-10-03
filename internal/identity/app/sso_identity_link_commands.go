package app

import (
	"context"
	"net/mail"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// The reader proves current ownership and email equality while holding both
// parent rows through commit. It never exposes provider material or user PII.
type SSOIdentityLinkWriteReader interface {
	LockSSOIdentityLinkWrites(context.Context, string) error
	ValidateSSOIdentityLinkTargets(context.Context, string, string, string, string) error
}
type SSOIdentityLinkTransaction interface {
	SSOIdentityLinkWriteReader
	application.Authorizer
	application.AuditAppender
	InsertUserIdentityLink(context.Context, identitydomain.UserIdentityLink) error
}
type SSOIdentityLinkTransactions interface {
	ExecuteSSOIdentityLink(context.Context, func(context.Context, SSOIdentityLinkTransaction) error) error
}
type SSOIdentityLinkCommandConfig struct {
	Transactions SSOIdentityLinkTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type SSOIdentityLinkCommands struct{ config SSOIdentityLinkCommandConfig }

func NewSSOIdentityLinkCommands(c SSOIdentityLinkCommandConfig) (*SSOIdentityLinkCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SSOIdentityLinkCommands{c}, nil
}
func normalizeSSOIdentityLinkInput(tenant string, in LinkSSOIdentityInput) (LinkSSOIdentityInput, error) {
	if !validAPIKeyText(in.UserID, 1024) || !validAPIKeyText(in.ProviderID, 1024) || !validAPIKeyText(in.Subject, MaxMembershipKeyBytes) || !validAPIKeyText(in.Email, MaxMembershipKeyBytes) {
		return in, ErrValidation
	}
	in.UserID, in.ProviderID, in.Subject = strings.TrimSpace(in.UserID), strings.TrimSpace(in.ProviderID), strings.TrimSpace(in.Subject)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	// Bound the indexed (tenant, provider, subject) identity below PostgreSQL's
	// B-tree tuple limit, even for incompressible UTF-8 values.
	if in.UserID == "" || in.ProviderID == "" || in.Subject == "" || !in.Verified || len(tenant)+len(in.ProviderID)+len(in.Subject) > MaxMembershipKeyBytes || len(tenant)+len(in.Email) > MaxMembershipKeyBytes {
		return in, ErrValidation
	}
	address, err := mail.ParseAddress(in.Email)
	if err != nil || address.Name != "" || address.Address != in.Email {
		return in, ErrValidation
	}
	return in, nil
}
func (s *SSOIdentityLinkCommands) prepare(ctx context.Context, a identitydomain.Actor, in LinkSSOIdentityInput) (LinkSSOIdentityInput, error) {
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
	return normalizeSSOIdentityLinkInput(a.TenantID, in)
}
func (s *SSOIdentityLinkCommands) execute(ctx context.Context, a identitydomain.Actor, in LinkSSOIdentityInput, run func(context.Context, SSOIdentityLinkTransaction) error) error {
	return s.config.Transactions.ExecuteSSOIdentityLink(ctx, func(ctx context.Context, tx SSOIdentityLinkTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, a, membershipAuthorization()); err != nil {
			return err
		}
		if err := tx.LockSSOIdentityLinkWrites(ctx, a.TenantID); err != nil {
			return err
		}
		if err := tx.ValidateSSOIdentityLinkTargets(ctx, a.TenantID, in.UserID, in.ProviderID, in.Email); err != nil {
			return err
		}
		if err := run(ctx, tx); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func (s *SSOIdentityLinkCommands) AuthorizeLinkSSOIdentity(ctx context.Context, a identitydomain.Actor, in LinkSSOIdentityInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, in, func(context.Context, SSOIdentityLinkTransaction) error { return nil })
}
func (s *SSOIdentityLinkCommands) LinkSSOIdentity(ctx context.Context, a identitydomain.Actor, in LinkSSOIdentityInput) (identitydomain.UserIdentityLink, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return identitydomain.UserIdentityLink{}, err
	}
	var out identitydomain.UserIdentityLink
	err = s.execute(ctx, a, in, func(ctx context.Context, tx SSOIdentityLinkTransaction) error {
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || !validAPIKeyTime(now) {
			return ErrValidation
		}
		out = identitydomain.UserIdentityLink{ID: s.config.IDs.NewID("uil"), TenantID: a.TenantID, UserID: in.UserID, ProviderID: in.ProviderID, Subject: in.Subject, Email: in.Email, Verified: true, SchemaVersion: userIdentityLinkSchemaVersion, CreatedAt: now}
		if !validAPIKeyID(out.ID) {
			return ErrValidation
		}
		if err := tx.InsertUserIdentityLink(ctx, out); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "identity_link.created", SubjectType: "human_user", SubjectID: in.UserID, ActorType: actorType(a), ActorID: actorID(a), OccurredAt: now}
		if !validAPIKeyID(audit.ID) {
			return ErrValidation
		}
		_, err := tx.AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return identitydomain.UserIdentityLink{}, err
	}
	return out, nil
}
