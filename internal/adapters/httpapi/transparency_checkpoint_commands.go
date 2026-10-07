package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func decodeTransparencyCheckpointRequest(body []byte) (verificationapp.CreateTransparencyCheckpointInput, error) {
	var req struct {
		BatchID     string `json:"batch_id"`
		Provider    string `json:"provider"`
		ExternalURL string `json:"external_url"`
		ExternalID  string `json:"external_id"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return verificationapp.CreateTransparencyCheckpointInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "batch_id", "provider", "external_url", "external_id"); err != nil {
		return verificationapp.CreateTransparencyCheckpointInput{}, err
	}
	in, err := verificationapp.NormalizeTransparencyCheckpointInput(verificationapp.CreateTransparencyCheckpointInput{BatchID: req.BatchID, Provider: req.Provider, ExternalURL: req.ExternalURL, ExternalID: req.ExternalID})
	return in, mapSigningKeyCommandError(err)
}

func (s *Server) createTransparencyCheckpoint(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in verificationapp.CreateTransparencyCheckpointInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeTransparencyCheckpointRequest(body)
		if err != nil {
			return err
		}
		return mapSigningKeyCommandError(s.transparencyCheckpointCommands.AuthorizeTransparencyCheckpoint(ctx, a, in.BatchID))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.transparencyCheckpointCommands.CreateTransparencyCheckpoint(ctx, a, in)
		return http.StatusCreated, domain.TransparencyCheckpoint(v), mapSigningKeyCommandError(err)
	})
}
