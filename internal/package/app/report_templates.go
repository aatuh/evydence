package app

import (
	"context"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const MaxStoredReportTemplateBytes = 8 << 20

type CreateReportTemplateInput struct {
	Name          string
	Version       string
	ReportType    string
	AllowedFields []string
	Template      string
}

type RenderReportInput struct {
	TemplateID  string
	SubjectType string
	SubjectID   string
}

type TemplateTransaction interface {
	GetCustomReportTemplate(context.Context, string, string) (packagedomain.CustomReportTemplate, error)
	InsertCustomReportTemplate(context.Context, packagedomain.CustomReportTemplate) error
	InsertRenderedCustomReport(context.Context, packagedomain.RenderedCustomReport) error
	application.Authorizer
	application.AuditAppender
}

type TemplateTransactions interface {
	ExecuteReportTemplate(context.Context, func(context.Context, TemplateTransaction) error) error
}

type ReportOutputHasher interface {
	HashReportOutput(context.Context, map[string]any) (string, error)
}

type TemplateCommandConfig struct {
	Transactions TemplateTransactions
	Authorizer   application.Authorizer
	Hasher       ReportOutputHasher
	Clock        application.Clock
	IDs          application.IDGenerator
}

// TemplateCommands stores inert template definitions and materializes only
// explicitly allowed metadata. Lookup, report writes, and audit share a unit
// of work, with no process cache or arbitrary subject lookup.
type TemplateCommands struct{ config TemplateCommandConfig }

func NewTemplateCommands(config TemplateCommandConfig) (*TemplateCommands, error) {
	if config.Transactions == nil || config.Authorizer == nil || config.Hasher == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &TemplateCommands{config}, nil
}

// CreateCustomReportTemplate stores a data-only template definition. The
// template text is never executed by RenderCustomReport.
func (s *TemplateCommands) CreateCustomReportTemplate(ctx context.Context, actor identitydomain.Actor, input CreateReportTemplateInput) (packagedomain.CustomReportTemplate, error) {
	if err := contextError(ctx); err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReportRead, ScopeOnly: true}); err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	input.Name, input.Version, input.ReportType = strings.TrimSpace(input.Name), strings.TrimSpace(input.Version), strings.TrimSpace(input.ReportType)
	fields, err := normalizedNonEmptyStrings(input.AllowedFields, true)
	if err != nil || input.Name == "" || input.Version == "" || input.ReportType == "" || len(fields) == 0 || int64(len(input.Template)) > ReportTemplateRequestLimit {
		return packagedomain.CustomReportTemplate{}, ErrValidation
	}
	now := s.config.Clock.Now().UTC()
	template := packagedomain.CustomReportTemplate{
		ID: s.config.IDs.NewID("rptpl"), TenantID: actor.TenantID, Name: input.Name, Version: input.Version,
		ReportType: input.ReportType, AllowedFields: fields, Template: strings.TrimSpace(input.Template),
		SchemaVersion: packagedomain.ReportTemplateSchemaVersion, CreatedAt: now,
	}
	err = s.config.Transactions.ExecuteReportTemplate(ctx, func(ctx context.Context, tx TemplateTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReportRead, TenantWide: true}); err != nil {
			return err
		}
		if err := tx.InsertCustomReportTemplate(ctx, template); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, s.auditEvent(actor, now, "report_template.created", "report_template", template.ID, ""))
		return err
	})
	if err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	return cloneCustomReportTemplate(template), nil
}

// RenderCustomReport selects only the versioned template's named safe fields
// and records the materialized output atomically with its audit entry.
func (s *TemplateCommands) RenderCustomReport(ctx context.Context, actor identitydomain.Actor, input RenderReportInput) (packagedomain.RenderedCustomReport, error) {
	if err := contextError(ctx); err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReportRead, ScopeOnly: true}); err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	if strings.TrimSpace(input.TemplateID) == "" || strings.TrimSpace(input.SubjectType) == "" || strings.TrimSpace(input.SubjectID) == "" {
		return packagedomain.RenderedCustomReport{}, ErrValidation
	}
	var report packagedomain.RenderedCustomReport
	err := s.config.Transactions.ExecuteReportTemplate(ctx, func(ctx context.Context, tx TemplateTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReportRead, TenantWide: true}); err != nil {
			return err
		}
		template, err := tx.GetCustomReportTemplate(ctx, actor.TenantID, strings.TrimSpace(input.TemplateID))
		if err != nil {
			return err
		}
		if template.TenantID != actor.TenantID || template.ID != strings.TrimSpace(input.TemplateID) {
			return ErrNotFound
		}
		now := s.config.Clock.Now().UTC()
		source := map[string]any{
			"subject_type": input.SubjectType,
			"subject_id":   input.SubjectID,
			"generated_at": now.Format(time.RFC3339),
		}
		output := map[string]any{}
		for _, field := range template.AllowedFields {
			if value, ok := source[field]; ok {
				output[field] = value
			}
		}
		hash, err := s.config.Hasher.HashReportOutput(ctx, output)
		if err != nil {
			return err
		}
		if strings.TrimSpace(hash) == "" {
			return ErrValidation
		}
		report = packagedomain.RenderedCustomReport{
			ID: s.config.IDs.NewID("rr"), TenantID: actor.TenantID, TemplateID: template.ID,
			SubjectType: strings.TrimSpace(input.SubjectType), SubjectID: strings.TrimSpace(input.SubjectID),
			Output: output, Hash: hash, SchemaVersion: "rendered-report.v1.0.0", CreatedAt: now,
		}
		if err := tx.InsertRenderedCustomReport(ctx, report); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, s.auditEvent(actor, now, "report_template.rendered", "rendered_report", report.ID, hash))
		return err
	})
	if err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	return cloneRenderedCustomReport(report), nil
}

func (s *TemplateCommands) auditEvent(actor identitydomain.Actor, at time.Time, entryType, subjectType, subjectID, hash string) application.AuditEvent {
	return application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: entryType, SubjectType: subjectType, SubjectID: subjectID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at, PayloadHash: hash}
}

func (s *Service) templateCommands() (*TemplateCommands, error) {
	return NewTemplateCommands(TemplateCommandConfig{Transactions: serviceTemplateTransactions{s.transactions}, Authorizer: s.authorizer, Hasher: serviceReportOutputHasher{s.canonicalizer}, Clock: s.clock, IDs: s.ids})
}
func (s *Service) CreateCustomReportTemplate(ctx context.Context, actor identitydomain.Actor, input CreateReportTemplateInput) (packagedomain.CustomReportTemplate, error) {
	commands, err := s.templateCommands()
	if err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	return commands.CreateCustomReportTemplate(ctx, actor, input)
}
func (s *Service) RenderCustomReport(ctx context.Context, actor identitydomain.Actor, input RenderReportInput) (packagedomain.RenderedCustomReport, error) {
	commands, err := s.templateCommands()
	if err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	return commands.RenderCustomReport(ctx, actor, input)
}

type serviceReportOutputHasher struct{ hasher ManifestCanonicalizer }

func (h serviceReportOutputHasher) HashReportOutput(ctx context.Context, output map[string]any) (string, error) {
	return h.hasher.HashPackageManifest(ctx, output)
}

type serviceTemplateTransactions struct{ transactions TransactionRunner }

func (t serviceTemplateTransactions) ExecuteReportTemplate(ctx context.Context, command func(context.Context, TemplateTransaction) error) error {
	return t.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, serviceTemplateTransaction{tx.Packages(), tx.Authorization(), tx.Audit()})
	})
}

type serviceTemplateTransaction struct {
	Repository
	application.Authorizer
	application.AuditAppender
}

func cloneCustomReportTemplate(value packagedomain.CustomReportTemplate) packagedomain.CustomReportTemplate {
	value.AllowedFields = append([]string(nil), value.AllowedFields...)
	return value
}

func cloneRenderedCustomReport(value packagedomain.RenderedCustomReport) packagedomain.RenderedCustomReport {
	value.Output = cloneBundleMap(value.Output)
	return value
}
