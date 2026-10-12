package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func controlReportFilters(r *http.Request, requireProduct bool) (packagequery.ControlCoverageFilter, error) {
	var empty packagequery.ControlCoverageFilter
	if r == nil || r.URL == nil {
		return empty, app.ErrValidation
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return empty, app.ErrValidation
	}
	for key, entries := range values {
		switch key {
		case "framework_id", "product_id", "release_id":
			if requireProduct && key == "framework_id" || len(entries) != 1 || strings.TrimSpace(entries[0]) == "" {
				return empty, app.ErrValidation
			}
		default:
			return empty, app.ErrValidation
		}
	}
	filter := packagequery.ControlCoverageFilter{
		FrameworkID: strings.TrimSpace(values.Get("framework_id")),
		ProductID:   strings.TrimSpace(values.Get("product_id")),
		ReleaseID:   strings.TrimSpace(values.Get("release_id")),
	}
	if requireProduct && filter.ProductID == "" {
		return empty, app.ErrValidation
	}
	return filter, nil
}

func mapControlCoverageQueryError(err error) error {
	switch {
	case errors.Is(err, packagequery.ErrControlCoverageValidation):
		return app.ErrValidation
	case errors.Is(err, packagequery.ErrControlCoverageNotFound):
		return app.ErrNotFound
	case errors.Is(err, packagequery.ErrControlCoverageProjection), errors.Is(err, packagequery.ErrControlCoverageCapacity):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}

func controlCoverageFromQuery(report packagedomain.ControlCoverageReport) domain.ControlCoverageReport {
	return domain.ControlCoverageReport{
		ReportType: report.ReportType, TemplateVersion: report.TemplateVersion,
		FrameworkID: report.FrameworkID, ProductID: report.ProductID, ReleaseID: report.ReleaseID,
		Result: report.Result, Controls: controlCoverageItemsFromQuery(report.Controls),
		MissingEvidence: report.MissingEvidence, AcceptedExceptions: controlReportExceptionsFromQuery(report.AcceptedExceptions),
		Assumptions: report.Assumptions, Limitations: report.Limitations, GeneratedAt: report.GeneratedAt,
	}
}

func craReadinessFromQuery(report packagedomain.CRAReadinessReport) domain.CRAReadinessReport {
	return domain.CRAReadinessReport{
		ReportType: report.ReportType, TemplateVersion: report.TemplateVersion,
		ProductID: report.ProductID, ReleaseID: report.ReleaseID, Result: report.Result,
		Controls: controlCoverageItemsFromQuery(report.Controls), MissingEvidence: report.MissingEvidence,
		AcceptedExceptions: controlReportExceptionsFromQuery(report.AcceptedExceptions),
		Assumptions:        report.Assumptions, Limitations: report.Limitations, GeneratedAt: report.GeneratedAt,
	}
}

func controlCoverageItemsFromQuery(values []packagedomain.ControlCoverageItem) []domain.ControlCoverageItem {
	items := make([]domain.ControlCoverageItem, 0, len(values))
	for _, value := range values {
		links := make([]domain.ControlEvidence, 0, len(value.LinkedEvidence))
		for _, link := range value.LinkedEvidence {
			links = append(links, controlEvidenceFromQuery(riskdomain.ControlEvidence{
				ID: link.ID, TenantID: link.TenantID, ControlID: link.ControlID,
				EvidenceType: link.EvidenceType, SubjectType: link.SubjectType, SubjectID: link.SubjectID,
				ProductID: link.ProductID, ReleaseID: link.ReleaseID, Confidence: link.Confidence,
				Notes: link.Notes, SchemaVersion: link.SchemaVersion, CreatedAt: link.CreatedAt,
			}))
		}
		items = append(items, domain.ControlCoverageItem{
			ControlID: value.ControlID, Code: value.Code, Title: value.Title,
			Status: value.Status, Confidence: value.Confidence, LinkedEvidence: links,
			Missing: value.Missing, Explanation: value.Explanation, Limitations: value.Limitations,
		})
	}
	return items
}

func controlReportExceptionsFromQuery(values []packagedomain.AcceptedExceptionSnapshot) []domain.Exception {
	exceptions := make([]domain.Exception, 0, len(values))
	for _, value := range values {
		exceptions = append(exceptions, domain.Exception{
			ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID,
			FindingID: value.FindingID, ControlID: value.ControlID, Reason: value.Reason,
			Owner: value.Owner, ExpiresAt: value.ExpiresAt, Approved: value.Approved,
			ApprovedBy: value.ApprovedBy, ApprovedAt: copyDecisionSummaryTime(value.ApprovedAt),
			CreatedAt: value.CreatedAt,
		})
	}
	return exceptions
}
