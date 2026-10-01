package query

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var (
	ErrIncidentReportValidation = errors.New("invalid incident report query")
	ErrIncidentReportNotFound   = errors.New("incident report not found")
	ErrIncidentReportProjection = errors.New("invalid incident report projection")
)

// IncidentReportSnapshot contains one current incident and its tenant-scoped
// timeline and tasks from a single committed database view.
type IncidentReportSnapshot struct {
	Incident operationsdomain.Incident
	Timeline []operationsdomain.IncidentTimelineEvent
	Tasks    []operationsdomain.RemediationTask
}

type IncidentReportReader interface {
	ReadIncidentReport(context.Context, string, string) (IncidentReportSnapshot, error)
}

type IncidentReport struct {
	reader IncidentReportReader
	now    func() time.Time
}

func NewIncidentReport(reader IncidentReportReader, now func() time.Time) (*IncidentReport, error) {
	if reader == nil || now == nil {
		return nil, ErrIncidentReportValidation
	}
	return &IncidentReport{reader: reader, now: now}, nil
}

func (s *IncidentReport) Report(ctx context.Context, actor identitydomain.Actor, id string) (packagedomain.IncidentReport, error) {
	var empty packagedomain.IncidentReport
	if s == nil || ctx == nil {
		return empty, ErrIncidentReportValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return empty, application.ErrUnauthorized
	}
	if !actor.HasScope("incident:read") && !actor.HasScope("admin") {
		return empty, application.ErrForbidden
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return empty, ErrIncidentReportNotFound
	}
	snapshot, err := s.reader.ReadIncidentReport(ctx, actor.TenantID, id)
	if err != nil {
		return empty, err
	}
	incident := snapshot.Incident
	if incident.ID != id || incident.TenantID != actor.TenantID || incident.ProductID == "" || incident.Status.IsZero() {
		return empty, ErrIncidentReportNotFound
	}
	if !incidentReportAllowed(actor, incident.ProductID, incident.ReleaseID) {
		return empty, application.ErrForbidden
	}
	timeline := make([]packagedomain.IncidentTimelineEventSnapshot, 0, len(snapshot.Timeline))
	tasks := make([]packagedomain.RemediationTaskSnapshot, 0, len(snapshot.Tasks))
	linked := make([]string, 0, len(snapshot.Timeline)+len(snapshot.Tasks))
	for _, event := range snapshot.Timeline {
		if event.ID == "" || event.TenantID != actor.TenantID || event.IncidentID != id {
			return empty, ErrIncidentReportProjection
		}
		timeline = append(timeline, packagedomain.IncidentTimelineEventSnapshot{
			ID: event.ID, TenantID: event.TenantID, IncidentID: event.IncidentID,
			EventType: event.EventType, Summary: event.Summary, EvidenceID: event.EvidenceID,
			OccurredAt: event.OccurredAt, SchemaVersion: event.SchemaVersion, CreatedAt: event.CreatedAt,
		})
		if event.EvidenceID != "" {
			linked = append(linked, strings.TrimSpace(event.EvidenceID))
		}
	}
	for _, task := range snapshot.Tasks {
		if task.ID == "" || task.TenantID != actor.TenantID || task.IncidentID != id {
			return empty, ErrIncidentReportProjection
		}
		tasks = append(tasks, packagedomain.RemediationTaskSnapshot{
			ID: task.ID, TenantID: task.TenantID, IncidentID: task.IncidentID,
			ReleaseID: task.ReleaseID, Title: task.Title, Owner: task.Owner, Status: task.Status,
			DueAt: task.DueAt, EvidenceID: task.EvidenceID, SchemaVersion: task.SchemaVersion,
			CreatedAt: task.CreatedAt,
		})
		if task.EvidenceID != "" {
			linked = append(linked, strings.TrimSpace(task.EvidenceID))
		}
	}
	sort.Slice(timeline, func(i, j int) bool {
		if timeline[i].OccurredAt.Equal(timeline[j].OccurredAt) {
			return timeline[i].ID < timeline[j].ID
		}
		return timeline[i].OccurredAt.Before(timeline[j].OccurredAt)
	})
	sort.Slice(tasks, func(i, j int) bool {
		if tasks[i].CreatedAt.Equal(tasks[j].CreatedAt) {
			return tasks[i].ID < tasks[j].ID
		}
		return tasks[i].CreatedAt.Before(tasks[j].CreatedAt)
	})
	sort.Strings(linked)
	result := "open"
	if incident.Status.String() == "closed" {
		result = "closed"
	}
	return packagedomain.IncidentReport{
		ReportType: "incident_package", TemplateVersion: "incident-package.v1.0.0",
		IncidentID: id, Result: result, Timeline: timeline, Tasks: tasks,
		LinkedEvidence: linked,
		Assumptions:    []string{"Incident evidence is limited to records stored in this Evydence tenant."},
		Limitations:    []string{"This report organizes incident evidence and does not prove root cause completeness or remediation sufficiency."},
		GeneratedAt:    s.now(),
	}, nil
}

func incidentReportAllowed(actor identitydomain.Actor, productID, releaseID string) bool {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true
	}
	for _, grant := range actor.ResourceGrants {
		allowedScope := false
		for _, scope := range grant.Scopes {
			if scope == "incident:read" || scope == "admin" || scope == "*" {
				allowedScope = true
				break
			}
		}
		if !allowedScope {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true
			}
		case "product":
			if grant.ResourceID == productID {
				return true
			}
		case "release":
			if releaseID != "" && grant.ResourceID == releaseID {
				return true
			}
		}
	}
	return false
}
