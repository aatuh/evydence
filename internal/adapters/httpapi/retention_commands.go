package httpapi

import (
	"bytes"
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func decodeObjectRetentionCreationRequest(body []byte, tenant string) (verificationapp.CreateObjectRetentionPolicyInput, error) {
	var req struct {
		Name                    string `json:"name"`
		ObjectPrefix            string `json:"object_prefix"`
		ObjectKey               string `json:"object_key"`
		RequireLegalHold        bool   `json:"require_legal_hold"`
		Mode                    string `json:"mode"`
		RetentionDays           int    `json:"retention_days"`
		MaxVerificationAgeHours *int   `json:"max_verification_age_hours"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return verificationapp.CreateObjectRetentionPolicyInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "mode", "retention_days", "object_prefix", "object_key", "require_legal_hold", "max_verification_age_hours"); err != nil {
		return verificationapp.CreateObjectRetentionPolicyInput{}, err
	}
	age := 0
	if req.MaxVerificationAgeHours != nil {
		age = *req.MaxVerificationAgeHours
		if age < 1 || age > 8784 {
			return verificationapp.CreateObjectRetentionPolicyInput{}, app.ErrValidation
		}
	}
	in, err := verificationapp.NormalizeObjectRetentionPolicyInput(tenant, verificationapp.CreateObjectRetentionPolicyInput{Name: req.Name, Mode: req.Mode, ObjectPrefix: req.ObjectPrefix, ObjectKey: req.ObjectKey, RequireLegalHold: req.RequireLegalHold, RetentionDays: req.RetentionDays, MaxVerificationAgeHours: age})
	return in, mapSigningKeyCommandError(err)
}

func decodeObjectRetentionVerificationRequest(body []byte, id string) (string, error) {
	id, err := verificationapp.NormalizeObjectRetentionPolicyID(id)
	if err != nil {
		return "", mapSigningKeyCommandError(err)
	}
	// Preserve accepted legacy empty bodies; {} remains the documented form.
	if len(bytes.TrimSpace(body)) == 0 {
		return id, nil
	}
	if err := decodeMembershipJSON(body, &struct{}{}); err != nil {
		return "", err
	}
	return id, validateExactNonNullableObjectFields(body)
}

func (s *Server) createObjectRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in verificationapp.CreateObjectRetentionPolicyInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeObjectRetentionCreationRequest(body, a.TenantID)
		if err != nil {
			return err
		}
		return mapSigningKeyCommandError(s.retentionCommands.AuthorizeCreateObjectRetentionPolicy(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.retentionCommands.CreateObjectRetentionPolicy(ctx, a, in)
		return http.StatusCreated, domain.ObjectRetentionPolicyFromContextModel(v), mapSigningKeyCommandError(err)
	})
}

func (s *Server) verifyObjectRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var id string
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		id, err = decodeObjectRetentionVerificationRequest(body, r.PathValue("id"))
		if err != nil {
			return err
		}
		return mapSigningKeyCommandError(s.retentionCommands.AuthorizeVerifyObjectRetentionPolicy(ctx, a, id))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.retentionCommands.VerifyObjectRetentionPolicy(ctx, a, id)
		return http.StatusOK, domain.ObjectRetentionPolicyFromContextModel(v), mapSigningKeyCommandError(err)
	})
}
