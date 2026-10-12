package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func decodeArtifactSignatureCreation(body []byte) (verificationapp.CreateArtifactSignatureInput, error) {
	var req struct {
		ArtifactID       string          `json:"artifact_id"`
		Algorithm        string          `json:"algorithm"`
		KeyID            string          `json:"key_id"`
		Signature        string          `json:"signature"`
		Payload          json.RawMessage `json:"payload"`
		PayloadMediaType string          `json:"payload_media_type"`
	}
	var empty verificationapp.CreateArtifactSignatureInput
	if err := decodeMembershipJSON(body, &req); err != nil {
		return empty, err
	}
	if err := validateExactNonNullableObjectFields(body, "artifact_id", "algorithm", "key_id", "signature", "payload", "payload_media_type"); err != nil {
		return empty, err
	}
	if len(req.Payload) > 0 {
		var payload map[string]json.RawMessage
		if json.Unmarshal(req.Payload, &payload) != nil || payload == nil {
			return empty, app.ErrValidation
		}
	}
	in, err := verificationapp.NormalizeArtifactSignatureInput(verificationapp.CreateArtifactSignatureInput{ArtifactID: req.ArtifactID, Algorithm: req.Algorithm, KeyID: req.KeyID, Signature: req.Signature, RawPayload: req.Payload, PayloadMediaType: req.PayloadMediaType})
	return in, mapVerificationCommandError(err)
}

func (s *Server) createArtifactSignature(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in verificationapp.CreateArtifactSignatureInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeArtifactSignatureCreation(body)
		if err != nil {
			return err
		}
		return mapVerificationCommandError(s.artifactSignatureCommands.AuthorizeArtifactSignatureCreation(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.artifactSignatureCommands.CreateArtifactSignature(ctx, a, in)
		return http.StatusCreated, artifactSignatureFromQuery(v), mapVerificationCommandError(err)
	})
}
