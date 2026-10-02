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

type ExceptionCommands interface {
	AuthorizeCreateException(context.Context, identitydomain.Actor, riskapp.CreateExceptionInput) error
	CreateException(context.Context, identitydomain.Actor, riskapp.CreateExceptionInput) (riskdomain.Exception, error)
	AuthorizeApproveException(context.Context, identitydomain.Actor, string) error
	ApproveException(context.Context, identitydomain.Actor, string) (riskdomain.Exception, error)
}

func (s *Server) createDurableException(w http.ResponseWriter, r *http.Request) {
	var input riskapp.CreateExceptionInput
	s.createDurable(w, r, func(ctx context.Context, actor domain.Actor, body []byte) error {
		var req struct {
			ReleaseID string    `json:"release_id"`
			FindingID string    `json:"finding_id"`
			ControlID string    `json:"control_id"`
			Reason    string    `json:"reason"`
			Owner     string    `json:"owner"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "release_id", "finding_id", "control_id", "reason", "owner", "expires_at"); err != nil {
			return err
		}
		input = riskapp.CreateExceptionInput{ReleaseID: req.ReleaseID, FindingID: req.FindingID, ControlID: req.ControlID, Reason: req.Reason, Owner: req.Owner, ExpiresAt: req.ExpiresAt}
		return mapControlCommandError(s.exceptionCommands.AuthorizeCreateException(ctx, actor, input))
	}, func(ctx context.Context, actor domain.Actor, _ []byte) (int, any, error) {
		v, err := s.exceptionCommands.CreateException(ctx, actor, input)
		return http.StatusCreated, domain.Exception(v), mapControlCommandError(err)
	})
}
func (s *Server) approveDurableException(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.createDurable(w, r, func(ctx context.Context, actor domain.Actor, _ []byte) error {
		return mapControlCommandError(s.exceptionCommands.AuthorizeApproveException(ctx, actor, id))
	}, func(ctx context.Context, actor domain.Actor, _ []byte) (int, any, error) {
		v, err := s.exceptionCommands.ApproveException(ctx, actor, id)
		return http.StatusOK, domain.Exception(v), mapControlCommandError(err)
	})
}
