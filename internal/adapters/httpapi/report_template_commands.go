package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func reportTemplateFromCommands(value packagedomain.CustomReportTemplate) domain.CustomReportTemplate {
	return domain.CustomReportTemplate{ID: value.ID, TenantID: value.TenantID, Name: value.Name, Version: value.Version, ReportType: value.ReportType, AllowedFields: value.AllowedFields, Template: value.Template, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}
func renderedReportFromCommands(value packagedomain.RenderedCustomReport) domain.RenderedCustomReport {
	return domain.RenderedCustomReport{ID: value.ID, TenantID: value.TenantID, TemplateID: value.TemplateID, SubjectType: value.SubjectType, SubjectID: value.SubjectID, Output: value.Output, Hash: value.Hash, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}
