package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type IncidentWebhookCommands interface {
	AuthorizeCreateIncidentWebhookReceiver(context.Context, identitydomain.Actor, operationsapp.CreateIncidentWebhookReceiverInput) error
	CreateIncidentWebhookReceiver(context.Context, identitydomain.Actor, operationsapp.CreateIncidentWebhookReceiverInput) (operationsdomain.IncidentWebhookReceiver, error)
	HandleIncidentWebhook(context.Context, operationsapp.HandleIncidentWebhookInput) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error)
}

func (s *Server) createDurableIncidentWebhookReceiver(w http.ResponseWriter, r *http.Request) {
	var in operationsapp.CreateIncidentWebhookReceiverInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			Name      string `json:"name"`
			Provider  string `json:"provider"`
			PublicKey string `json:"public_key"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "name", "provider", "public_key"); err != nil {
			return err
		}
		in = operationsapp.CreateIncidentWebhookReceiverInput{IncidentID: r.PathValue("id"), Name: req.Name, Provider: req.Provider, PublicKey: req.PublicKey}
		return mapDeploymentCommandError(s.incidentWebhookCommands.AuthorizeCreateIncidentWebhookReceiver(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.incidentWebhookCommands.CreateIncidentWebhookReceiver(ctx, a, in)
		return http.StatusCreated, domain.IncidentWebhookReceiver(v), mapDeploymentCommandError(err)
	})
}
func (s *Server) receiveDurableIncidentWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	eventID, err := requiredSingleHeader(r, "X-Evydence-Webhook-Event-ID")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	stamp, err := requiredSingleHeader(r, "X-Evydence-Webhook-Timestamp")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	signature, err := requiredSingleHeader(r, "X-Evydence-Webhook-Signature")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		writeProblem(w, r, app.ErrValidation)
		return
	}
	v, e, err := s.incidentWebhookCommands.HandleIncidentWebhook(r.Context(), operationsapp.HandleIncidentWebhookInput{ReceiverID: r.PathValue("receiver_id"), EventID: eventID, Timestamp: at, Signature: signature, Body: body})
	if err != nil {
		writeProblem(w, r, mapDeploymentCommandError(err))
		return
	}
	writeData(w, http.StatusCreated, map[string]any{"webhook_event": domain.IncidentWebhookEvent(v), "timeline_event": domain.IncidentTimelineEvent(e)})
}
