package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type WaiverCommands interface {
	AuthorizeCreateWaiver(context.Context, identitydomain.Actor, riskapp.CreateWaiverInput) error
	CreateWaiver(context.Context, identitydomain.Actor, riskapp.CreateWaiverInput) (riskdomain.Waiver, error)
	AuthorizeApproveWaiver(context.Context, identitydomain.Actor, string) error
	ApproveWaiver(context.Context, identitydomain.Actor, string) (riskdomain.Waiver, error)
}

func (s *Server) createDurableWaiver(w http.ResponseWriter, r *http.Request) {
	var input riskapp.CreateWaiverInput
	s.createDurable(w, r, func(ctx context.Context, actor domain.Actor, body []byte) error {
		var req struct {
			ScopeType  string    `json:"scope_type"`
			ScopeID    string    `json:"scope_id"`
			ControlID  string    `json:"control_id"`
			PolicyID   string    `json:"policy_id"`
			Owner      string    `json:"owner"`
			Risk       string    `json:"risk"`
			Reason     string    `json:"reason"`
			ExpiresAt  time.Time `json:"expires_at"`
			Supersedes string    `json:"supersedes"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "scope_type", "scope_id", "control_id", "policy_id", "owner", "risk", "reason", "expires_at", "supersedes"); err != nil {
			return err
		}
		input = riskapp.CreateWaiverInput{ScopeType: req.ScopeType, ScopeID: req.ScopeID, ControlID: req.ControlID, PolicyID: req.PolicyID, Owner: req.Owner, Risk: req.Risk, Reason: req.Reason, ExpiresAt: req.ExpiresAt, Supersedes: req.Supersedes}
		return mapControlCommandError(s.waiverCommands.AuthorizeCreateWaiver(ctx, actor, input))
	}, func(ctx context.Context, actor domain.Actor, _ []byte) (int, any, error) {
		v, err := s.waiverCommands.CreateWaiver(ctx, actor, input)
		return http.StatusCreated, domain.Waiver(v), mapControlCommandError(err)
	})
}
func (s *Server) approveDurableWaiver(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.createDurable(w, r, func(ctx context.Context, actor domain.Actor, _ []byte) error {
		return mapControlCommandError(s.waiverCommands.AuthorizeApproveWaiver(ctx, actor, id))
	}, func(ctx context.Context, actor domain.Actor, _ []byte) (int, any, error) {
		v, err := s.waiverCommands.ApproveWaiver(ctx, actor, id)
		return http.StatusOK, domain.Waiver(v), mapControlCommandError(err)
	})
}
