package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// Unchanged aggregate behavior is retained only as a characterization oracle.
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

func (l *Ledger) CreateCustomReportTemplate(ctx context.Context, actor domain.Actor, in CreateReportTemplateInput) (domain.CustomReportTemplate, error) {
	value, err := l.packageCommands.CreateCustomReportTemplate(ctx, actor, packageapp.CreateReportTemplateInput{
		Name: in.Name, Version: in.Version, ReportType: in.ReportType,
		AllowedFields: append([]string(nil), in.AllowedFields...), Template: in.Template,
	})
	return customReportTemplateFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) RenderCustomReport(ctx context.Context, actor domain.Actor, in RenderReportInput) (domain.RenderedCustomReport, error) {
	value, err := l.packageCommands.RenderCustomReport(ctx, actor, packageapp.RenderReportInput{
		TemplateID: in.TemplateID, SubjectType: in.SubjectType, SubjectID: in.SubjectID,
	})
	return renderedCustomReportFromPackageContext(value), fromPackageContextError(err)
}

func (l *Ledger) ImportEvidenceBundle(ctx context.Context, actor domain.Actor, bundle domain.EvidenceBundle) (domain.EvidenceBundleImport, error) {
	value, err := l.packageCommands.ImportEvidenceBundle(ctx, actor, evidenceBundleToPackageContext(bundle))
	return evidenceBundleImportFromPackageContext(value), fromPackageContextError(err)
}
