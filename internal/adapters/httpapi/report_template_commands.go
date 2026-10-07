package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func decodeReportTemplateCreation(body []byte) (packageapp.CreateReportTemplateInput, error) {
	var r struct {
		Name          string   `json:"name"`
		Version       string   `json:"version"`
		ReportType    string   `json:"report_type"`
		AllowedFields []string `json:"allowed_fields"`
		Template      string   `json:"template"`
	}
	if err := decodeMembershipJSON(body, &r); err != nil {
		return packageapp.CreateReportTemplateInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "version", "report_type", "allowed_fields", "template"); err != nil {
		return packageapp.CreateReportTemplateInput{}, err
	}
	if err := validateNonNullableArrayItems(body, "allowed_fields"); err != nil {
		return packageapp.CreateReportTemplateInput{}, err
	}
	in := packageapp.CreateReportTemplateInput{Name: r.Name, Version: r.Version, ReportType: r.ReportType, AllowedFields: r.AllowedFields, Template: r.Template}
	_, err := packageapp.NormalizeReportTemplateCreation(in)
	return in, mapCustomerPackageAccessError(err)
}
func decodeReportRendering(body []byte, id string) (packageapp.RenderReportInput, error) {
	var r struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	if err := decodeMembershipJSON(body, &r); err != nil {
		return packageapp.RenderReportInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "subject_type", "subject_id"); err != nil {
		return packageapp.RenderReportInput{}, err
	}
	in := packageapp.RenderReportInput{TemplateID: id, SubjectType: r.SubjectType, SubjectID: r.SubjectID}
	_, err := packageapp.NormalizeReportRendering(in)
	return in, mapCustomerPackageAccessError(err)
}

func (s *Server) createReportTemplate(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in packageapp.CreateReportTemplateInput
	s.createDurableWithLimit(w, r, app.ReportTemplateRequestLimit, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeReportTemplateCreation(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.reportTemplateCommands.AuthorizeReportTemplateCreation(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.reportTemplateCommands.CreateCustomReportTemplate(ctx, a, in)
		return 201, reportTemplateFromCommands(v), mapCustomerPackageAccessError(err)
	})
}

func (s *Server) renderReportTemplate(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in packageapp.RenderReportInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeReportRendering(body, r.PathValue("id"))
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.reportTemplateCommands.AuthorizeReportRendering(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.reportTemplateCommands.RenderCustomReport(ctx, a, in)
		return 201, renderedReportFromCommands(v), mapCustomerPackageAccessError(err)
	})
}

func reportTemplateFromCommands(value packagedomain.CustomReportTemplate) domain.CustomReportTemplate {
	return domain.CustomReportTemplate{ID: value.ID, TenantID: value.TenantID, Name: value.Name, Version: value.Version, ReportType: value.ReportType, AllowedFields: value.AllowedFields, Template: value.Template, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}
func renderedReportFromCommands(value packagedomain.RenderedCustomReport) domain.RenderedCustomReport {
	return domain.RenderedCustomReport{ID: value.ID, TenantID: value.TenantID, TemplateID: value.TemplateID, SubjectType: value.SubjectType, SubjectID: value.SubjectID, Output: value.Output, Hash: value.Hash, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}
