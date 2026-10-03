package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// ControlTemplateTransaction installs one static pack atomically. Its only read
// is version-key existence; it cannot read tenant inventories or foreign data.
type ControlTemplateTransaction interface {
	application.Authorizer
	application.AuditAppender
	FrameworkVersionReader
	InsertControlFramework(context.Context, riskdomain.ControlFramework) error
	InsertSecurityControl(context.Context, riskdomain.SecurityControl) error
}
type ControlTemplateTransactionRunner interface {
	ExecuteControlTemplate(context.Context, func(context.Context, ControlTemplateTransaction) error) error
}
type ControlTemplateCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions ControlTemplateTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ControlTemplateCommands struct{ config ControlTemplateCommandConfig }

func NewControlTemplateCommands(config ControlTemplateCommandConfig) (*ControlTemplateCommands, error) {
	if config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ControlTemplateCommands{config: config}, nil
}

func (s *ControlTemplateCommands) InstallControlFrameworkTemplatePack(ctx context.Context, actor identitydomain.Actor, slug string) (riskdomain.ControlFramework, error) {
	if s == nil {
		return riskdomain.ControlFramework{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return riskdomain.ControlFramework{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, controlAdminRequest()); err != nil {
		return riskdomain.ControlFramework{}, err
	}
	slug = strings.TrimSpace(slug)
	if !validControlText(slug, 1024, false) || !validControlText(actor.TenantID, 1024, true) {
		return riskdomain.ControlFramework{}, ErrValidation
	}
	var selected riskdomain.ControlFrameworkTemplatePack
	for _, pack := range riskdomain.BuiltinTemplatePacks() {
		if pack.Slug == slug {
			selected = pack
			break
		}
	}
	if selected.ID == "" {
		return riskdomain.ControlFramework{}, ErrNotFound
	}
	var created riskdomain.ControlFramework
	err := s.config.Transactions.ExecuteControlTemplate(ctx, func(ctx context.Context, tx ControlTemplateTransaction) error {
		if err := tx.Authorize(ctx, actor, controlAdminRequest()); err != nil {
			return err
		}
		if exists, err := tx.FrameworkVersionExists(ctx, actor.TenantID, selected.Slug, selected.Version); err != nil {
			return err
		} else if exists {
			return ErrConflict
		}
		created = riskdomain.ControlFramework{ID: s.config.IDs.NewID("cf"), TenantID: actor.TenantID, Name: selected.Name, Slug: selected.Slug, Version: selected.Version, Description: selected.Description, Status: "active", SchemaVersion: riskdomain.ControlFrameworkSchemaVersion, CreatedAt: s.config.Clock.Now().UTC()}
		if !validControlText(created.ID, 1024, true) || created.CreatedAt.IsZero() {
			return ErrValidation
		}
		if err := tx.InsertControlFramework(ctx, created); err != nil {
			return err
		}
		for _, template := range selected.Controls {
			control := cloneTemplateControl(template)
			control.ID = s.config.IDs.NewID("ctrl")
			control.TenantID = actor.TenantID
			control.FrameworkID = created.ID
			control.SchemaVersion = riskdomain.SecurityControlSchemaVersion
			control.CreatedAt = s.config.Clock.Now().UTC()
			if !validControlText(control.ID, 1024, true) || control.CreatedAt.IsZero() {
				return ErrValidation
			}
			if err := tx.InsertSecurityControl(ctx, control); err != nil {
				return err
			}
		}
		_, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: "control_framework_template.installed", SubjectType: "control_framework", SubjectID: created.ID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: created.CreatedAt})
		return err
	})
	if err != nil {
		return riskdomain.ControlFramework{}, err
	}
	return created, nil
}

func cloneTemplateControl(v riskdomain.SecurityControl) riskdomain.SecurityControl {
	v.EvidenceRequirements = append([]riskdomain.ControlEvidenceRequirement(nil), v.EvidenceRequirements...)
	v.Applicability = append([]string(nil), v.Applicability...)
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}
