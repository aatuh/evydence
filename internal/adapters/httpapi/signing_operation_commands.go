package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type SigningOperationCommands interface {
	AuthorizeCreateSigningOperation(context.Context, identitydomain.Actor, verificationapp.SigningOperationInput) error
	CreateSigningOperation(context.Context, identitydomain.Actor, verificationapp.SigningOperationInput) (verificationdomain.SigningOperation, error)
}

func mapSigningOperationCommandError(err error) error {
	if errors.Is(err, verificationapp.ErrVerificationFailed) {
		return app.ErrVerificationFailed
	}
	return mapSigningKeyCommandError(err)
}
func decodeSigningOperationRequest(body []byte) (verificationapp.SigningOperationInput, error) {
	var req struct {
		ProviderID  string `json:"provider_id"`
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
		PayloadHash string `json:"payload_hash"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return verificationapp.SigningOperationInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "provider_id", "subject_type", "subject_id", "payload_hash"); err != nil {
		return verificationapp.SigningOperationInput{}, err
	}
	v, err := verificationapp.NormalizeSigningOperationInput(verificationapp.SigningOperationInput{ProviderID: req.ProviderID, SubjectType: req.SubjectType, SubjectID: req.SubjectID, PayloadHash: req.PayloadHash})
	return v, mapSigningOperationCommandError(err)
}
func (s *Server) createDurableSigningOperation(w http.ResponseWriter, r *http.Request) {
	var in verificationapp.SigningOperationInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeSigningOperationRequest(body)
		if err != nil {
			return err
		}
		return mapSigningOperationCommandError(s.signingOperationCommands.AuthorizeCreateSigningOperation(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.signingOperationCommands.CreateSigningOperation(ctx, a, in)
		if err != nil {
			return 0, nil, mapSigningOperationCommandError(err)
		}
		raw, err := verificationapp.EncodeSigningOperation(v)
		return http.StatusCreated, json.RawMessage(raw), err
	})
}
