package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func decodeRetentionMarkerRequest(body []byte, override bool) (operationsapp.RetentionOverrideInput, error) {
	var req struct {
		ScopeType      string    `json:"scope_type"`
		ScopeID        string    `json:"scope_id"`
		Reason         string    `json:"reason"`
		Owner          string    `json:"owner"`
		RetentionUntil time.Time `json:"retention_until"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return operationsapp.RetentionOverrideInput{}, err
	}
	fields := []string{"scope_type", "scope_id", "reason", "owner"}
	if override {
		fields = append(fields, "retention_until")
	}
	if err := validateExactNonNullableObjectFields(body, fields...); err != nil {
		return operationsapp.RetentionOverrideInput{}, err
	}
	in := operationsapp.RetentionOverrideInput{RetentionMarkerInput: operationsapp.RetentionMarkerInput{ScopeType: req.ScopeType, ScopeID: req.ScopeID, Reason: req.Reason, Owner: req.Owner}, RetentionUntil: req.RetentionUntil}
	if override {
		v, err := operationsapp.NormalizeRetentionOverrideInput(in)
		return v, mapDeploymentCommandError(err)
	}
	v, err := operationsapp.NormalizeRetentionMarkerInput(in.RetentionMarkerInput)
	in.RetentionMarkerInput = v
	return in, mapDeploymentCommandError(err)
}
func (s *Server) createRetentionMarker(w http.ResponseWriter, r *http.Request, override bool) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in operationsapp.RetentionOverrideInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeRetentionMarkerRequest(body, override)
		if err != nil {
			return err
		}
		return mapDeploymentCommandError(s.retentionMarkerCommands.AuthorizeRetentionMarker(ctx, a, in.ScopeType, in.ScopeID))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		if override {
			v, err := s.retentionMarkerCommands.CreateRetentionOverride(ctx, a, in)
			return http.StatusCreated, domain.RetentionOverride(v), mapDeploymentCommandError(err)
		}
		v, err := s.retentionMarkerCommands.CreateLegalHold(ctx, a, in.RetentionMarkerInput)
		return http.StatusCreated, domain.LegalHold(v), mapDeploymentCommandError(err)
	})
}
