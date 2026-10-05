package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// ControlCommands exposes manual framework/control creation only. Template
// installation, evidence linking, and query capabilities are separate ports.
type ControlCommands interface {
	AuthorizeControlFrameworkCreation(context.Context, identitydomain.Actor, riskapp.CreateControlFrameworkInput) error
	AuthorizeSecurityControlCreation(context.Context, identitydomain.Actor, riskapp.CreateSecurityControlInput) error
	CreateControlFramework(context.Context, identitydomain.Actor, riskapp.CreateControlFrameworkInput) (riskdomain.ControlFramework, error)
	CreateSecurityControl(context.Context, identitydomain.Actor, riskapp.CreateSecurityControlInput) (riskdomain.SecurityControl, error)
}

func decodeControlFrameworkCreation(body []byte) (riskapp.CreateControlFrameworkInput, error) {
	var req struct {
		Name        string `json:"name"`
		Slug        string `json:"slug"`
		Version     string `json:"version"`
		Description string `json:"description"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return riskapp.CreateControlFrameworkInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "slug", "version", "description"); err != nil {
		return riskapp.CreateControlFrameworkInput{}, err
	}
	v, err := riskapp.NormalizeControlFrameworkInput(riskapp.CreateControlFrameworkInput{Name: req.Name, Slug: req.Slug, Version: req.Version, Description: req.Description})
	return v, mapControlCommandError(err)
}

func decodeSecurityControlCreation(body []byte) (riskapp.CreateSecurityControlInput, error) {
	var req struct {
		FrameworkID          string                              `json:"framework_id"`
		Code                 string                              `json:"code"`
		Title                string                              `json:"title"`
		Objective            string                              `json:"objective"`
		EvidenceRequirements []domain.ControlEvidenceRequirement `json:"evidence_requirements"`
		Applicability        []string                            `json:"applicability"`
		Limitations          []string                            `json:"limitations"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return riskapp.CreateSecurityControlInput{}, err
	}
	if err := validateSecurityControlJSON(body); err != nil {
		return riskapp.CreateSecurityControlInput{}, err
	}
	reqs := make([]riskdomain.ControlEvidenceRequirement, 0, len(req.EvidenceRequirements))
	for _, v := range req.EvidenceRequirements {
		reqs = append(reqs, riskdomain.ControlEvidenceRequirement{Type: v.Type, FreshnessDays: v.FreshnessDays, Required: v.Required})
	}
	v, err := riskapp.NormalizeSecurityControlInput(riskapp.CreateSecurityControlInput{FrameworkID: req.FrameworkID, Code: req.Code, Title: req.Title, Objective: req.Objective, EvidenceRequirements: reqs, Applicability: req.Applicability, Limitations: req.Limitations})
	return v, mapControlCommandError(err)
}

func localControlFrameworkInput(in riskapp.CreateControlFrameworkInput) app.CreateControlFrameworkInput {
	return app.CreateControlFrameworkInput{Name: in.Name, Slug: in.Slug, Version: in.Version, Description: in.Description}
}
func localSecurityControlInput(in riskapp.CreateSecurityControlInput) app.CreateSecurityControlInput {
	reqs := make([]domain.ControlEvidenceRequirement, 0, len(in.EvidenceRequirements))
	for _, r := range in.EvidenceRequirements {
		reqs = append(reqs, domain.ControlEvidenceRequirement{Type: r.Type, FreshnessDays: r.FreshnessDays, Required: r.Required})
	}
	return app.CreateSecurityControlInput{FrameworkID: in.FrameworkID, Code: in.Code, Title: in.Title, Objective: in.Objective, EvidenceRequirements: reqs, Applicability: in.Applicability, Limitations: in.Limitations}
}

func (s *Server) createControlFramework(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in riskapp.CreateControlFrameworkInput
	if s.controlCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeControlFrameworkCreation(body)
			if err != nil {
				return err
			}
			return mapControlCommandError(s.controlCommands.AuthorizeControlFrameworkCreation(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.controlCommands.CreateControlFramework(ctx, a, in)
			return http.StatusCreated, controlFrameworkFromQuery(v), mapControlCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.ledger.CreateControlFramework(ctx, a, localControlFrameworkInput(in))
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeControlFrameworkCreation(body)
		if err != nil {
			return nil, err
		}
		return body, s.ledger.AuthorizeControlFrameworkCreation(r.Context(), a, localControlFrameworkInput(in))
	})
}

func (s *Server) createSecurityControl(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in riskapp.CreateSecurityControlInput
	if s.controlCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeSecurityControlCreation(body)
			if err != nil {
				return err
			}
			return mapControlCommandError(s.controlCommands.AuthorizeSecurityControlCreation(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.controlCommands.CreateSecurityControl(ctx, a, in)
			return http.StatusCreated, securityControlFromQuery(v), mapControlCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.ledger.CreateSecurityControl(ctx, a, localSecurityControlInput(in))
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeSecurityControlCreation(body)
		if err != nil {
			return nil, err
		}
		return body, s.ledger.AuthorizeSecurityControlCreation(r.Context(), a, localSecurityControlInput(in))
	})
}

func mapControlCommandError(err error) error {
	switch {
	case errors.Is(err, riskapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, riskapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, riskapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}

// validateSecurityControlJSON runs after strict decodeJSON. It distinguishes
// absent optional arrays from explicit null and enforces the published required
// boolean on each evidence requirement (false is valid; absence is not).
func validateSecurityControlJSON(body []byte) error {
	if err := validateNonNullableObjectFields(body, "framework_id", "code", "title", "objective", "evidence_requirements", "applicability", "limitations"); err != nil {
		return err
	}
	for _, name := range []string{"evidence_requirements", "applicability", "limitations"} {
		if err := validateNonNullableArrayItems(body, name); err != nil {
			return err
		}
	}
	var input struct {
		Requirements []map[string]json.RawMessage `json:"evidence_requirements"`
	}
	if len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, &input); err != nil {
		return app.ErrValidation
	}
	for i, fields := range input.Requirements {
		for _, name := range []string{"type", "required", "freshness_days"} {
			raw, present := fields[name]
			if !present && name == "freshness_days" {
				continue
			}
			if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return app.NewValidationError(app.FieldViolation{Field: "/evidence_requirements/" + strconv.Itoa(i) + "/" + name, Code: "invalid_type"})
			}
		}
	}
	return nil
}
