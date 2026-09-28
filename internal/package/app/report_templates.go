package app

import (
	"context"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

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

// CreateCustomReportTemplate stores a data-only template definition. The
// template text is never executed by RenderCustomReport.
func (s *Service) CreateCustomReportTemplate(ctx context.Context, actor identitydomain.Actor, input CreateReportTemplateInput) (packagedomain.CustomReportTemplate, error) {
	if err := contextError(ctx); err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReportRead, application.ResourceReferences{}, true); err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	input.Name, input.Version, input.ReportType = strings.TrimSpace(input.Name), strings.TrimSpace(input.Version), strings.TrimSpace(input.ReportType)
	fields, err := normalizedNonEmptyStrings(input.AllowedFields, true)
	if err != nil || input.Name == "" || input.Version == "" || input.ReportType == "" || len(fields) == 0 || int64(len(input.Template)) > ReportTemplateRequestLimit {
		return packagedomain.CustomReportTemplate{}, ErrValidation
	}
	now := s.clock.Now().UTC()
	template := packagedomain.CustomReportTemplate{
		ID: s.ids.NewID("rptpl"), TenantID: actor.TenantID, Name: input.Name, Version: input.Version,
		ReportType: input.ReportType, AllowedFields: fields, Template: strings.TrimSpace(input.Template),
		SchemaVersion: packagedomain.ReportTemplateSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReportRead, TenantWide: true}); err != nil {
			return err
		}
		if err := tx.Packages().InsertCustomReportTemplate(ctx, template); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "report_template.created", "report_template", template.ID, ""))
		return err
	})
	if err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	return cloneCustomReportTemplate(template), nil
}

// RenderCustomReport selects only the versioned template's named safe fields
// and records the materialized output atomically with its audit entry.
func (s *Service) RenderCustomReport(ctx context.Context, actor identitydomain.Actor, input RenderReportInput) (packagedomain.RenderedCustomReport, error) {
	if err := contextError(ctx); err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReportRead, application.ResourceReferences{}, true); err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	template, err := s.reader.GetCustomReportTemplate(ctx, actor.TenantID, strings.TrimSpace(input.TemplateID))
	if err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	if template.TenantID != actor.TenantID {
		return packagedomain.RenderedCustomReport{}, ErrNotFound
	}
	now := s.clock.Now().UTC()
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
	hash, err := s.canonicalizer.HashPackageManifest(ctx, output)
	if err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	if strings.TrimSpace(hash) == "" {
		return packagedomain.RenderedCustomReport{}, ErrValidation
	}
	report := packagedomain.RenderedCustomReport{
		ID: s.ids.NewID("rr"), TenantID: actor.TenantID, TemplateID: template.ID,
		SubjectType: strings.TrimSpace(input.SubjectType), SubjectID: strings.TrimSpace(input.SubjectID),
		Output: output, Hash: hash, SchemaVersion: "rendered-report.v1.0.0", CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReportRead, TenantWide: true}); err != nil {
			return err
		}
		if err := tx.Packages().InsertRenderedCustomReport(ctx, report); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "report_template.rendered", "rendered_report", report.ID, hash))
		return err
	})
	if err != nil {
		return packagedomain.RenderedCustomReport{}, err
	}
	return cloneRenderedCustomReport(report), nil
}

func cloneCustomReportTemplate(value packagedomain.CustomReportTemplate) packagedomain.CustomReportTemplate {
	value.AllowedFields = append([]string(nil), value.AllowedFields...)
	return value
}

func cloneRenderedCustomReport(value packagedomain.RenderedCustomReport) packagedomain.RenderedCustomReport {
	value.Output = cloneBundleMap(value.Output)
	return value
}
