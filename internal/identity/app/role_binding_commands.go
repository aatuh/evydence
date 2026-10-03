package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Targets are resolved and held in the same transaction as assignment/audit.
// Identity commands do not receive other contexts' repositories or payloads.
type RoleBindingWriteReader interface {
	GrantTargetResolver
	LockRoleBindingWrites(context.Context, string) error
}
type RoleBindingTransaction interface {
	RoleBindingWriteReader
	application.Authorizer
	application.AuditAppender
	InsertRoleBinding(context.Context, identitydomain.RoleBinding) error
}
type RoleBindingTransactions interface {
	ExecuteRoleBinding(context.Context, func(context.Context, RoleBindingTransaction) error) error
}
type RoleBindingCommandConfig struct {
	Transactions RoleBindingTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type RoleBindingCommands struct{ config RoleBindingCommandConfig }

func NewRoleBindingCommands(c RoleBindingCommandConfig) (*RoleBindingCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &RoleBindingCommands{c}, nil
}

func normalizeRoleBindingInput(tenant string, in CreateRoleBindingInput) (CreateRoleBindingInput, error) {
	if !validAPIKeyText(in.SubjectType, 128) || !validAPIKeyText(in.SubjectID, 1024) || !validAPIKeyText(in.Role, 128) || !validAPIKeyText(in.ResourceType, 128) || !validAPIKeyText(in.ResourceID, 1024) {
		return in, ErrValidation
	}
	in.SubjectType, in.SubjectID, in.Role = strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID), strings.TrimSpace(in.Role)
	in.ResourceType, in.ResourceID = strings.TrimSpace(in.ResourceType), strings.TrimSpace(in.ResourceID)
	if !validRoleSubject(in.SubjectType) || in.SubjectID == "" || !validRole(in.Role) {
		return in, ErrValidation
	}
	switch in.ResourceType {
	case "":
		if in.ResourceID != "" {
			return in, ErrValidation
		}
	case "tenant":
		if in.ResourceID != "" && in.ResourceID != tenant {
			return in, ErrNotFound
		}
	case "product", "project", "release", "customer_security_package", "evidence_bundle":
		if in.ResourceID == "" {
			return in, ErrNotFound
		}
	default:
		return in, ErrValidation
	}
	return in, nil
}
func (s *RoleBindingCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateRoleBindingInput) (CreateRoleBindingInput, error) {
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
	return normalizeRoleBindingInput(a.TenantID, in)
}
func (s *RoleBindingCommands) execute(ctx context.Context, a identitydomain.Actor, in CreateRoleBindingInput, run func(context.Context, RoleBindingTransaction) error) error {
	return s.config.Transactions.ExecuteRoleBinding(ctx, func(ctx context.Context, tx RoleBindingTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, a, membershipAuthorization()); err != nil {
			return err
		}
		if err := tx.LockRoleBindingWrites(ctx, a.TenantID); err != nil {
			return err
		}
		if err := tx.ValidateSubject(ctx, a.TenantID, in.SubjectType, in.SubjectID); err != nil {
			return err
		}
		if err := tx.ValidateResource(ctx, a.TenantID, in.ResourceType, in.ResourceID); err != nil {
			return err
		}
		if err := run(ctx, tx); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func (s *RoleBindingCommands) AuthorizeCreateRoleBinding(ctx context.Context, a identitydomain.Actor, in CreateRoleBindingInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, in, func(context.Context, RoleBindingTransaction) error { return nil })
}
func (s *RoleBindingCommands) CreateRoleBinding(ctx context.Context, a identitydomain.Actor, in CreateRoleBindingInput) (identitydomain.RoleBinding, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return identitydomain.RoleBinding{}, err
	}
	var out identitydomain.RoleBinding
	err = s.execute(ctx, a, in, func(ctx context.Context, tx RoleBindingTransaction) error {
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || !validAPIKeyTime(now) {
			return ErrValidation
		}
		out = identitydomain.RoleBinding{ID: s.config.IDs.NewID("rbac"), TenantID: a.TenantID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, Role: in.Role, ResourceType: in.ResourceType, ResourceID: in.ResourceID, SchemaVersion: identitydomain.RoleBindingSchemaVersion, CreatedAt: now}
		if !validAPIKeyID(out.ID) {
			return ErrValidation
		}
		if err := tx.InsertRoleBinding(ctx, out); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "role_binding.created", SubjectType: "role_binding", SubjectID: out.ID, ActorType: actorType(a), ActorID: actorID(a), OccurredAt: now}
		if !validAPIKeyID(audit.ID) {
			return ErrValidation
		}
		_, err := tx.AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return identitydomain.RoleBinding{}, err
	}
	return out, nil
}
