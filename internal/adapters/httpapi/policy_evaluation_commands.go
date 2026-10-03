package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type PolicyEvaluationCommands interface {
	AuthorizeEvaluateRelease(context.Context, identitydomain.Actor, string) error
	EvaluateRelease(context.Context, identitydomain.Actor, string) (riskdomain.PolicyEvaluation, error)
}

func (s *Server) evaluateDurablePolicy(w http.ResponseWriter, r *http.Request) {
	var release string
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			ReleaseID string `json:"release_id"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "release_id"); err != nil {
			return err
		}
		release = req.ReleaseID
		return mapControlCommandError(s.policyEvaluationCommands.AuthorizeEvaluateRelease(ctx, a, release))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.policyEvaluationCommands.EvaluateRelease(ctx, a, release)
		return http.StatusCreated, domain.PolicyEvaluationFromContext(v), mapControlCommandError(err)
	})
}
