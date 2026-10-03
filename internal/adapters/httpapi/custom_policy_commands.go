package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type CustomPolicyCommands interface {
	AuthorizeCreateCustomPolicy(context.Context, identitydomain.Actor, riskapp.CreateCustomPolicyInput) error
	CreateCustomPolicy(context.Context, identitydomain.Actor, riskapp.CreateCustomPolicyInput) (riskdomain.CustomPolicy, error)
	AuthorizeEvaluateCustomPolicy(context.Context, identitydomain.Actor, string, string) error
	EvaluateCustomPolicy(context.Context, identitydomain.Actor, string, string) (riskdomain.CustomPolicyEvaluation, error)
}

func (s *Server) createDurableCustomPolicy(w http.ResponseWriter, r *http.Request) {
	var in riskapp.CreateCustomPolicyInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			Name        string              `json:"name"`
			Version     string              `json:"version"`
			Description string              `json:"description"`
			Rules       []domain.PolicyRule `json:"rules"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "name", "version", "description", "rules"); err != nil {
			return err
		}
		if err := validateNonNullableArrayItems(body, "rules"); err != nil {
			return err
		}
		var raw struct {
			Rules []json.RawMessage `json:"rules"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return err
		}
		for _, rule := range raw.Rules {
			if err := validateNonNullableObjectFields(rule, "name", "evidence_type", "severity", "required"); err != nil {
				return err
			}
		}
		rules := make([]riskdomain.PolicyRule, len(req.Rules))
		for i, rule := range req.Rules {
			rules[i] = riskdomain.PolicyRule(rule)
		}
		in = riskapp.CreateCustomPolicyInput{Name: req.Name, Version: req.Version, Description: req.Description, Rules: rules}
		return mapControlCommandError(s.customPolicyCommands.AuthorizeCreateCustomPolicy(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		p, err := s.customPolicyCommands.CreateCustomPolicy(ctx, a, in)
		return http.StatusCreated, domain.CustomPolicyFromContext(p), mapControlCommandError(err)
	})
}
func (s *Server) evaluateDurableCustomPolicy(w http.ResponseWriter, r *http.Request) {
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
		return mapControlCommandError(s.customPolicyCommands.AuthorizeEvaluateCustomPolicy(ctx, a, r.PathValue("id"), release))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.customPolicyCommands.EvaluateCustomPolicy(ctx, a, r.PathValue("id"), release)
		return http.StatusCreated, domain.CustomPolicyEvaluationFromContext(v), mapControlCommandError(err)
	})
}
