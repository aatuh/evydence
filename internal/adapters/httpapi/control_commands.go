package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// ControlCommands exposes manual framework/control creation only. Template
// installation, evidence linking, and query capabilities are separate ports.
type ControlCommands interface {
	CreateControlFramework(context.Context, identitydomain.Actor, riskapp.CreateControlFrameworkInput) (riskdomain.ControlFramework, error)
	CreateSecurityControl(context.Context, identitydomain.Actor, riskapp.CreateSecurityControlInput) (riskdomain.SecurityControl, error)
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
