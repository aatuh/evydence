package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type IncidentCommands interface {
	AuthorizeCreateIncident(context.Context, identitydomain.Actor, operationsapp.CreateIncidentInput) error
	AuthorizeRecordIncidentTimelineEvent(context.Context, identitydomain.Actor, string, operationsapp.RecordIncidentTimelineInput) error
	AuthorizeCreateRemediationTask(context.Context, identitydomain.Actor, operationsapp.CreateRemediationTaskInput) error
	CreateIncident(context.Context, identitydomain.Actor, operationsapp.CreateIncidentInput) (operationsdomain.Incident, error)
	RecordIncidentTimelineEvent(context.Context, identitydomain.Actor, string, operationsapp.RecordIncidentTimelineInput) (operationsdomain.IncidentTimelineEvent, error)
	CreateRemediationTask(context.Context, identitydomain.Actor, operationsapp.CreateRemediationTaskInput) (operationsdomain.RemediationTask, error)
}

func (s *Server) createDurableIncident(w http.ResponseWriter, r *http.Request) {
	var in operationsapp.CreateIncidentInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			ProductID string    `json:"product_id"`
			ReleaseID string    `json:"release_id"`
			Title     string    `json:"title"`
			Severity  string    `json:"severity"`
			OpenedAt  time.Time `json:"opened_at"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "product_id", "release_id", "title", "severity", "opened_at"); err != nil {
			return err
		}
		in = operationsapp.CreateIncidentInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, Title: req.Title, Severity: req.Severity, OpenedAt: req.OpenedAt}
		return mapDeploymentCommandError(s.incidentCommands.AuthorizeCreateIncident(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.incidentCommands.CreateIncident(ctx, a, in)
		return http.StatusCreated, domain.IncidentFromContextModel(v), mapDeploymentCommandError(err)
	})
}
func (s *Server) recordDurableIncidentTimeline(w http.ResponseWriter, r *http.Request) {
	var in operationsapp.RecordIncidentTimelineInput
	id := r.PathValue("id")
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			EventType  string    `json:"event_type"`
			Summary    string    `json:"summary"`
			EvidenceID string    `json:"evidence_id"`
			OccurredAt time.Time `json:"occurred_at"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "event_type", "summary", "evidence_id", "occurred_at"); err != nil {
			return err
		}
		in = operationsapp.RecordIncidentTimelineInput{EventType: req.EventType, Summary: req.Summary, EvidenceID: req.EvidenceID, OccurredAt: req.OccurredAt}
		return mapDeploymentCommandError(s.incidentCommands.AuthorizeRecordIncidentTimelineEvent(ctx, a, id, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.incidentCommands.RecordIncidentTimelineEvent(ctx, a, id, in)
		return http.StatusCreated, domain.IncidentTimelineEvent(v), mapDeploymentCommandError(err)
	})
}
func (s *Server) createDurableRemediationTask(w http.ResponseWriter, r *http.Request) {
	var in operationsapp.CreateRemediationTaskInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			IncidentID string     `json:"incident_id"`
			ReleaseID  string     `json:"release_id"`
			Title      string     `json:"title"`
			Owner      string     `json:"owner"`
			DueAt      *time.Time `json:"due_at"`
			EvidenceID string     `json:"evidence_id"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "incident_id", "release_id", "title", "owner", "due_at", "evidence_id"); err != nil {
			return err
		}
		in = operationsapp.CreateRemediationTaskInput{IncidentID: req.IncidentID, ReleaseID: req.ReleaseID, Title: req.Title, Owner: req.Owner, DueAt: req.DueAt, EvidenceID: req.EvidenceID}
		return mapDeploymentCommandError(s.incidentCommands.AuthorizeCreateRemediationTask(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.incidentCommands.CreateRemediationTask(ctx, a, in)
		return http.StatusCreated, domain.RemediationTask(v), mapDeploymentCommandError(err)
	})
}
