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
)

func releaseReportFilters(r *http.Request) (string, string, error) {
	if r == nil || r.URL == nil {
		return "", "", app.ErrValidation
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", "", app.ErrValidation
	}
	for key, entries := range values {
		if key != "product_id" && key != "release_id" || len(entries) != 1 || strings.TrimSpace(entries[0]) == "" {
			return "", "", app.ErrValidation
		}
	}
	productID, releaseID := strings.TrimSpace(values.Get("product_id")), strings.TrimSpace(values.Get("release_id"))
	if productID == "" || releaseID == "" {
		return "", "", app.ErrValidation
	}
	return productID, releaseID, nil
}

func mapReportDecisions(values []packagedomain.VulnerabilityDecisionSnapshot) []domain.VulnerabilityDecisionCustomerSummary {
	decisions := make([]domain.VulnerabilityDecisionCustomerSummary, 0, len(values))
	for _, decision := range values {
		refs := make([]domain.SubjectRef, 0, len(decision.SupportingRefs))
		for _, ref := range decision.SupportingRefs {
			refs = append(refs, domain.SubjectRef{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
		}
		decisions = append(decisions, domain.VulnerabilityDecisionCustomerSummary{
			ID: decision.ID, FindingID: decision.FindingID, ScanID: decision.ScanID, ReleaseID: decision.ReleaseID,
			Vulnerability: decision.Vulnerability, Component: decision.Component, SBOMID: decision.SBOMID,
			SBOMComponentPURL: decision.SBOMComponentPURL, SBOMComponentName: decision.SBOMComponentName,
			Status: decision.Status, Justification: decision.Justification, ImpactStatement: decision.ImpactStatement,
			ActionStatement: decision.ActionStatement, Source: decision.Source, EvidenceID: decision.EvidenceID,
			EvidenceIDs: append([]string(nil), decision.EvidenceIDs...), SupportingRefs: refs,
			VEXDocumentID: decision.VEXDocumentID, ReviewedAt: copyDecisionSummaryTime(decision.ReviewedAt),
			ReviewDueAt: copyDecisionSummaryTime(decision.ReviewDueAt), CreatedAt: decision.CreatedAt,
		})
	}
	return decisions
}

func securityUpdateFromQuery(report packagedomain.SecurityUpdateEvidenceReport) domain.SecurityUpdateEvidenceReport {
	decisions := mapReportDecisions(report.FixedDecisions)
	incidents := make([]domain.Incident, 0, len(report.Incidents))
	for _, incident := range report.Incidents {
		incidents = append(incidents, domain.Incident{
			ID: incident.ID, TenantID: incident.TenantID, ProductID: incident.ProductID, ReleaseID: incident.ReleaseID,
			Title: incident.Title, Severity: incident.Severity, Status: incident.Status, OpenedAt: incident.OpenedAt,
			ClosedAt: incident.ClosedAt, SchemaVersion: incident.SchemaVersion, CreatedAt: incident.CreatedAt,
		})
	}
	tasks := make([]domain.RemediationTask, 0, len(report.RemediationTasks))
	for _, task := range report.RemediationTasks {
		tasks = append(tasks, domain.RemediationTask{
			ID: task.ID, TenantID: task.TenantID, IncidentID: task.IncidentID, ReleaseID: task.ReleaseID,
			Title: task.Title, Owner: task.Owner, Status: task.Status, DueAt: task.DueAt,
			EvidenceID: task.EvidenceID, SchemaVersion: task.SchemaVersion, CreatedAt: task.CreatedAt,
		})
	}
	return domain.SecurityUpdateEvidenceReport{
		ReportType: report.ReportType, TemplateVersion: report.TemplateVersion,
		ProductID: report.ProductID, ReleaseID: report.ReleaseID, Summary: report.Summary,
		FixedDecisions: decisions, Incidents: incidents, RemediationTasks: tasks,
		EvidenceIDs: report.EvidenceIDs, Assumptions: report.Assumptions,
		Limitations: report.Limitations, GeneratedAt: report.GeneratedAt,
	}
}

func mapSecurityUpdateQueryError(err error) error {
	switch {
	case errors.Is(err, packagequery.ErrSecurityUpdateValidation):
		return app.ErrValidation
	case errors.Is(err, packagequery.ErrSecurityUpdateNotFound):
		return app.ErrNotFound
	case errors.Is(err, packagequery.ErrSecurityUpdateProjection), errors.Is(err, packagequery.ErrSecurityUpdateCapacity):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
