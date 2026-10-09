package app

import (
	"context"
	"net/mail"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const MaxMembershipKeyBytes = 2304

type MembershipOrganization struct{ ID, TenantID string }
type MembershipWriteReader interface {
	LockMembershipWrites(context.Context, string) error
	OrganizationSlugExists(context.Context, string, string) (bool, error)
	UserEmailExists(context.Context, string, string) (bool, error)
	ReadMembershipOrganization(context.Context, string, string) (MembershipOrganization, error)
	ReadMembershipUser(context.Context, string, string) (identitydomain.HumanUser, error)
}
type MembershipTransaction interface {
	MembershipWriteReader
	application.Authorizer
	application.AuditAppender
	InsertOrganization(context.Context, identitydomain.Organization) error
	InsertHumanUser(context.Context, identitydomain.HumanUser) error
	DeactivateHumanUser(context.Context, identitydomain.HumanUser) error
}
type MembershipTransactions interface {
	ExecuteMembership(context.Context, func(context.Context, MembershipTransaction) error) error
}
type MembershipCommandConfig struct {
	Transactions MembershipTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type MembershipCommands struct{ config MembershipCommandConfig }

func NewMembershipCommands(c MembershipCommandConfig) (*MembershipCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &MembershipCommands{c}, nil
}

type membershipWriteAuthorizer struct{}

func NewMembershipWriteAuthorizer() application.Authorizer { return membershipWriteAuthorizer{} }
func (membershipWriteAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopeIdentityAdmin || r.ScopeOnly || !r.TenantWide || r.Resources != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return application.AuthorizeTenantWideScope(ctx, a, ScopeIdentityAdmin)
}
func membershipAuthorization() application.AuthorizationRequest {
	return application.AuthorizationRequest{Scope: ScopeIdentityAdmin, TenantWide: true}
}
func normalizeMembershipOrganization(tenant string, in CreateOrganizationInput) (CreateOrganizationInput, error) {
	if !validAPIKeyText(in.Name, 65536) || !validAPIKeyText(in.Slug, 65536) {
		return in, ErrValidation
	}
	in.Name, in.Slug = strings.TrimSpace(in.Name), strings.TrimSpace(in.Slug)
	if in.Name == "" || in.Slug == "" || len(tenant)+len(in.Slug) > MaxMembershipKeyBytes {
		return in, ErrValidation
	}
	return in, nil
}
func normalizeMembershipUser(tenant string, in CreateUserInput) (CreateUserInput, error) {
	if !validAPIKeyText(in.OrganizationID, 1024) || !validAPIKeyText(in.Email, MaxMembershipKeyBytes) || !validAPIKeyText(in.DisplayName, 65536) {
		return in, ErrValidation
	}
	in.OrganizationID, in.Email, in.DisplayName = strings.TrimSpace(in.OrganizationID), strings.ToLower(strings.TrimSpace(in.Email)), strings.TrimSpace(in.DisplayName)
	if in.DisplayName == "" || len(tenant)+len(in.Email) > MaxMembershipKeyBytes {
		return in, ErrValidation
	}
	address, err := mail.ParseAddress(in.Email)
	if err != nil || address.Name != "" || address.Address != in.Email {
		return in, ErrValidation
	}
	return in, nil
}
func (s *MembershipCommands) prepare(ctx context.Context, a identitydomain.Actor) error {
	if s == nil || ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, membershipAuthorization()); err != nil {
		return err
	}
	if !validAPIKeyID(a.TenantID) || !validAPIKeyID(actorID(a)) {
		return ErrValidation
	}
	return nil
}
func (s *MembershipCommands) execute(ctx context.Context, a identitydomain.Actor, fn func(context.Context, MembershipTransaction) error) error {
	return s.config.Transactions.ExecuteMembership(ctx, func(ctx context.Context, tx MembershipTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, a, membershipAuthorization()); err != nil {
			return err
		}
		if err := tx.LockMembershipWrites(ctx, a.TenantID); err != nil {
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func (s *MembershipCommands) now() (time.Time, error) {
	v := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if v.IsZero() || !validAPIKeyTime(v) {
		return v, ErrValidation
	}
	return v, nil
}
func (s *MembershipCommands) audit(ctx context.Context, tx MembershipTransaction, a identitydomain.Actor, now time.Time, action, kind, id string) error {
	v := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: action, SubjectType: kind, SubjectID: id, ActorType: actorType(a), ActorID: actorID(a), OccurredAt: now}
	if !validAPIKeyID(v.ID) {
		return ErrValidation
	}
	_, err := tx.AppendAudit(ctx, v)
	return err
}
func membershipOrganization(ctx context.Context, tx MembershipTransaction, tenant, id string) error {
	if id == "" {
		return nil
	}
	v, err := tx.ReadMembershipOrganization(ctx, tenant, id)
	if err != nil {
		return err
	}
	if v.ID != id || v.TenantID != tenant {
		return ErrNotFound
	}
	return nil
}

// Guards validate current authority and parents without checking duplicate
// identities or active status: completed creation/deactivation can replay.
func (s *MembershipCommands) AuthorizeCreateOrganization(ctx context.Context, a identitydomain.Actor, in CreateOrganizationInput) error {
	if err := s.prepare(ctx, a); err != nil {
		return err
	}
	if _, err := normalizeMembershipOrganization(a.TenantID, in); err != nil {
		return err
	}
	return s.execute(ctx, a, func(context.Context, MembershipTransaction) error { return nil })
}
func (s *MembershipCommands) AuthorizeCreateUser(ctx context.Context, a identitydomain.Actor, in CreateUserInput) error {
	if err := s.prepare(ctx, a); err != nil {
		return err
	}
	in, err := normalizeMembershipUser(a.TenantID, in)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, func(ctx context.Context, tx MembershipTransaction) error {
		return membershipOrganization(ctx, tx, a.TenantID, in.OrganizationID)
	})
}
func membershipUser(ctx context.Context, tx MembershipTransaction, tenant, id string) (identitydomain.HumanUser, error) {
	v, err := tx.ReadMembershipUser(ctx, tenant, id)
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	if v.ID != id || v.TenantID != tenant {
		return identitydomain.HumanUser{}, ErrNotFound
	}
	if err := membershipOrganization(ctx, tx, tenant, v.OrganizationID); err != nil {
		return identitydomain.HumanUser{}, err
	}
	return cloneHumanUser(v), nil
}
func (s *MembershipCommands) prepareUserID(ctx context.Context, a identitydomain.Actor, id string) (string, error) {
	if err := s.prepare(ctx, a); err != nil {
		return "", err
	}
	if !validAPIKeyText(id, 1024) {
		return "", ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", ErrValidation
	}
	return id, nil
}
func (s *MembershipCommands) AuthorizeDeactivateUser(ctx context.Context, a identitydomain.Actor, id string) error {
	id, err := s.prepareUserID(ctx, a, id)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, func(ctx context.Context, tx MembershipTransaction) error {
		_, err := membershipUser(ctx, tx, a.TenantID, id)
		return err
	})
}
func (s *MembershipCommands) CreateOrganization(ctx context.Context, a identitydomain.Actor, in CreateOrganizationInput) (identitydomain.Organization, error) {
	if err := s.prepare(ctx, a); err != nil {
		return identitydomain.Organization{}, err
	}
	in, err := normalizeMembershipOrganization(a.TenantID, in)
	if err != nil {
		return identitydomain.Organization{}, err
	}
	var out identitydomain.Organization
	err = s.execute(ctx, a, func(ctx context.Context, tx MembershipTransaction) error {
		exists, err := tx.OrganizationSlugExists(ctx, a.TenantID, in.Slug)
		if err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		now, err := s.now()
		if err != nil {
			return err
		}
		out = identitydomain.Organization{ID: s.config.IDs.NewID("org"), TenantID: a.TenantID, Name: in.Name, Slug: in.Slug, Status: "active", SchemaVersion: identitydomain.OrganizationSchemaVersion, CreatedAt: now}
		if !validAPIKeyID(out.ID) {
			return ErrValidation
		}
		if err := tx.InsertOrganization(ctx, out); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, now, "organization.created", "organization", out.ID)
	})
	if err != nil {
		return identitydomain.Organization{}, err
	}
	return out, nil
}
func (s *MembershipCommands) CreateUser(ctx context.Context, a identitydomain.Actor, in CreateUserInput) (identitydomain.HumanUser, error) {
	if err := s.prepare(ctx, a); err != nil {
		return identitydomain.HumanUser{}, err
	}
	in, err := normalizeMembershipUser(a.TenantID, in)
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	var out identitydomain.HumanUser
	err = s.execute(ctx, a, func(ctx context.Context, tx MembershipTransaction) error {
		if err := membershipOrganization(ctx, tx, a.TenantID, in.OrganizationID); err != nil {
			return err
		}
		exists, err := tx.UserEmailExists(ctx, a.TenantID, in.Email)
		if err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		now, err := s.now()
		if err != nil {
			return err
		}
		out = identitydomain.HumanUser{ID: s.config.IDs.NewID("usr"), TenantID: a.TenantID, OrganizationID: in.OrganizationID, Email: in.Email, DisplayName: in.DisplayName, Status: "active", SchemaVersion: identitydomain.HumanUserSchemaVersion, CreatedAt: now}
		if !validAPIKeyID(out.ID) {
			return ErrValidation
		}
		if err := tx.InsertHumanUser(ctx, cloneHumanUser(out)); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, now, "user.created", "human_user", out.ID)
	})
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	return cloneHumanUser(out), nil
}
func (s *MembershipCommands) DeactivateUser(ctx context.Context, a identitydomain.Actor, id string) (identitydomain.HumanUser, error) {
	id, err := s.prepareUserID(ctx, a, id)
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	var out identitydomain.HumanUser
	err = s.execute(ctx, a, func(ctx context.Context, tx MembershipTransaction) error {
		out, err = membershipUser(ctx, tx, a.TenantID, id)
		if err != nil {
			return err
		}
		if out.Status != "active" {
			return ErrConflict
		}
		now, err := s.now()
		if err != nil {
			return err
		}
		out.Status, out.DeactivatedAt = "deactivated", &now
		if err := tx.DeactivateHumanUser(ctx, cloneHumanUser(out)); err != nil {
			return err
		}
		return s.audit(ctx, tx, a, now, "user.deactivated", "human_user", out.ID)
	})
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	return cloneHumanUser(out), nil
}
