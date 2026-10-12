package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func incidentReportFromQuery(report packagedomain.IncidentReport) domain.IncidentReport {
	timeline := make([]domain.IncidentTimelineEvent, 0, len(report.Timeline))
	for _, event := range report.Timeline {
		timeline = append(timeline, domain.IncidentTimelineEvent{
			ID: event.ID, TenantID: event.TenantID, IncidentID: event.IncidentID,
			EventType: event.EventType, Summary: event.Summary, EvidenceID: event.EvidenceID,
			OccurredAt: event.OccurredAt, SchemaVersion: event.SchemaVersion,
			CreatedAt: event.CreatedAt,
		})
	}
	tasks := make([]domain.RemediationTask, 0, len(report.Tasks))
	for _, task := range report.Tasks {
		tasks = append(tasks, domain.RemediationTask{
			ID: task.ID, TenantID: task.TenantID, IncidentID: task.IncidentID,
			ReleaseID: task.ReleaseID, Title: task.Title, Owner: task.Owner,
			Status: task.Status, DueAt: task.DueAt, EvidenceID: task.EvidenceID,
			SchemaVersion: task.SchemaVersion, CreatedAt: task.CreatedAt,
		})
	}
	return domain.IncidentReport{
		ReportType: report.ReportType, TemplateVersion: report.TemplateVersion,
		IncidentID: report.IncidentID, Result: report.Result,
		Timeline: timeline, Tasks: tasks, LinkedEvidence: report.LinkedEvidence,
		Assumptions: report.Assumptions, Limitations: report.Limitations,
		GeneratedAt: report.GeneratedAt,
	}
}

func mapIncidentReportQueryError(err error) error {
	switch {
	case errors.Is(err, packagequery.ErrIncidentReportValidation):
		return app.ErrValidation
	case errors.Is(err, packagequery.ErrIncidentReportNotFound):
		return app.ErrNotFound
	case errors.Is(err, packagequery.ErrIncidentReportProjection):
		return app.ErrConflict
	case errors.Is(err, packagequery.ErrIncidentReportCapacity):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
