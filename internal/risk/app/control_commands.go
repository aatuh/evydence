package app

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const ScopeControlsAdmin = "controls:admin"

// ControlCreationReader transfers existence only, never a framework's metadata
// or an inventory of controls. All reads occur in the active write transaction.
type ControlCreationReader interface {
	FrameworkVersionExists(context.Context, string, string, string) (bool, error)
	ControlFrameworkExists(context.Context, string, string) (bool, error)
	SecurityControlCodeExists(context.Context, string, string, string) (bool, error)
}

type ControlTransaction interface {
	application.Authorizer
	application.AuditAppender
	ControlCreationReader
	InsertControlFramework(context.Context, riskdomain.ControlFramework) error
	InsertSecurityControl(context.Context, riskdomain.SecurityControl) error
}
type ControlTransactionRunner interface {
	ExecuteControls(context.Context, func(context.Context, ControlTransaction) error) error
}
type ControlCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions ControlTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ControlCommands struct{ config ControlCommandConfig }

func NewControlCommands(config ControlCommandConfig) (*ControlCommands, error) {
	if config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ControlCommands{config: config}, nil
}

type CreateControlFrameworkInput struct{ Name, Slug, Version, Description string }
type CreateSecurityControlInput struct {
	FrameworkID, Code, Title, Objective string
	EvidenceRequirements                []riskdomain.ControlEvidenceRequirement
	Applicability, Limitations          []string
}

func (s *ControlCommands) preflight(ctx context.Context, actor identitydomain.Actor) error {
	if s == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	return s.config.Authorizer.Authorize(ctx, actor, controlAdminRequest())
}
func controlAdminRequest() application.AuthorizationRequest {
	return application.AuthorizationRequest{Scope: ScopeControlsAdmin, TenantWide: true}
}

func (s *ControlCommands) CreateControlFramework(ctx context.Context, actor identitydomain.Actor, in CreateControlFrameworkInput) (riskdomain.ControlFramework, error) {
	if err := s.preflight(ctx, actor); err != nil {
		return riskdomain.ControlFramework{}, err
	}
	in.Name, in.Slug, in.Version, in.Description = strings.TrimSpace(in.Name), strings.TrimSpace(in.Slug), strings.TrimSpace(in.Version), strings.TrimSpace(in.Description)
	if in.Slug == "" {
		in.Slug = riskdomain.ControlFrameworkSlug(in.Name)
	}
	if !validControlText(actor.TenantID, 1024, true) || !validControlText(in.Name, 65536, true) || !validControlText(in.Slug, 1024, true) || !validControlText(in.Version, 1024, true) || len(in.Slug)+len(in.Version) > 1024 || !validControlText(in.Description, 65536, false) {
		return riskdomain.ControlFramework{}, ErrValidation
	}
	v := riskdomain.ControlFramework{ID: s.config.IDs.NewID("fw"), TenantID: actor.TenantID, Name: in.Name, Slug: in.Slug, Version: in.Version, Description: in.Description, Status: "active", SchemaVersion: riskdomain.ControlFrameworkSchemaVersion, CreatedAt: s.config.Clock.Now().UTC()}
	if !validControlText(v.ID, 1024, true) || v.CreatedAt.IsZero() {
		return riskdomain.ControlFramework{}, ErrValidation
	}
	err := s.config.Transactions.ExecuteControls(ctx, func(ctx context.Context, tx ControlTransaction) error {
		if err := tx.Authorize(ctx, actor, controlAdminRequest()); err != nil {
			return err
		}
		if exists, err := tx.FrameworkVersionExists(ctx, actor.TenantID, v.Slug, v.Version); err != nil {
			return err
		} else if exists {
			return ErrConflict
		}
		if err := tx.InsertControlFramework(ctx, v); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, s.audit(actor, v.CreatedAt, "control_framework", v.ID))
		return err
	})
	if err != nil {
		return riskdomain.ControlFramework{}, err
	}
	return v, nil
}

func (s *ControlCommands) CreateSecurityControl(ctx context.Context, actor identitydomain.Actor, in CreateSecurityControlInput) (riskdomain.SecurityControl, error) {
	if err := s.preflight(ctx, actor); err != nil {
		return riskdomain.SecurityControl{}, err
	}
	in.FrameworkID, in.Code, in.Title, in.Objective = strings.TrimSpace(in.FrameworkID), strings.TrimSpace(in.Code), strings.TrimSpace(in.Title), strings.TrimSpace(in.Objective)
	if !validControlText(actor.TenantID, 1024, true) || !validControlText(in.FrameworkID, 1024, true) || !validControlText(in.Code, 1024, true) || len(actor.TenantID)+len(in.FrameworkID)+len(in.Code) > 2048 || !validControlText(in.Title, 65536, true) || !validControlText(in.Objective, 65536, true) || len(in.EvidenceRequirements) > 10 || !validControlLists(in.Applicability, in.Limitations) {
		return riskdomain.SecurityControl{}, ErrValidation
	}
	requirements, err := riskdomain.NormalizeControlRequirements(in.EvidenceRequirements)
	if err != nil {
		return riskdomain.SecurityControl{}, ErrValidation
	}
	applicability := append([]string(nil), in.Applicability...)
	for i := range applicability {
		applicability[i] = strings.TrimSpace(applicability[i])
	}
	sort.Strings(applicability)
	limitations := []string{}
	for _, text := range in.Limitations {
		if trimmed := strings.TrimSpace(text); trimmed != "" {
			limitations = append(limitations, trimmed)
		}
	}
	v := riskdomain.SecurityControl{ID: s.config.IDs.NewID("ctrl"), TenantID: actor.TenantID, FrameworkID: in.FrameworkID, Code: in.Code, Title: in.Title, Objective: in.Objective, EvidenceRequirements: requirements, Applicability: applicability, Limitations: limitations, SchemaVersion: riskdomain.SecurityControlSchemaVersion, CreatedAt: s.config.Clock.Now().UTC()}
	if !validControlText(v.ID, 1024, true) || v.CreatedAt.IsZero() {
		return riskdomain.SecurityControl{}, ErrValidation
	}
	err = s.config.Transactions.ExecuteControls(ctx, func(ctx context.Context, tx ControlTransaction) error {
		if err := tx.Authorize(ctx, actor, controlAdminRequest()); err != nil {
			return err
		}
		if exists, err := tx.ControlFrameworkExists(ctx, actor.TenantID, v.FrameworkID); err != nil {
			return err
		} else if !exists {
			return ErrNotFound
		}
		if exists, err := tx.SecurityControlCodeExists(ctx, actor.TenantID, v.FrameworkID, v.Code); err != nil {
			return err
		} else if exists {
			return ErrConflict
		}
		if err := tx.InsertSecurityControl(ctx, cloneSecurityControl(v)); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, s.audit(actor, v.CreatedAt, "security_control", v.ID))
		return err
	})
	if err != nil {
		return riskdomain.SecurityControl{}, err
	}
	return v, nil
}

func validControlText(text string, limit int, required bool) bool {
	return (!required || text != "") && len(text) <= limit && utf8.ValidString(text) && !strings.ContainsRune(text, 0)
}
func validControlLists(groups ...[]string) bool {
	count, bytes := 0, 0
	for _, group := range groups {
		if len(group) > 1024-count {
			return false
		}
		count += len(group)
		for _, text := range group {
			if !validControlText(text, 65536, false) || len(text) > 65536-bytes {
				return false
			}
			bytes += len(text)
		}
	}
	return true
}
func cloneSecurityControl(v riskdomain.SecurityControl) riskdomain.SecurityControl {
	v.EvidenceRequirements = append([]riskdomain.ControlEvidenceRequirement{}, v.EvidenceRequirements...)
	v.Applicability = append([]string(nil), v.Applicability...)
	v.Limitations = append([]string{}, v.Limitations...)
	return v
}

func (s *ControlCommands) audit(actor identitydomain.Actor, at time.Time, subjectType, id string) application.AuditEvent {
	return application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: subjectType + ".created", SubjectType: subjectType, SubjectID: id, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at}
}
