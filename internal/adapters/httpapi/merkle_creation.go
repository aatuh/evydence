package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func decodeMerkleCreationRequest(body []byte) (verificationapp.CreateMerkleBatchInput, error) {
	var req struct {
		FromSequence int64 `json:"from_sequence"`
		ToSequence   int64 `json:"to_sequence"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return verificationapp.CreateMerkleBatchInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "from_sequence", "to_sequence"); err != nil {
		return verificationapp.CreateMerkleBatchInput{}, err
	}
	in := verificationapp.CreateMerkleBatchInput{FromSequence: req.FromSequence, ToSequence: req.ToSequence}
	return in, mapSigningKeyCommandError(verificationapp.ValidateMerkleCreationInput(in))
}

func (s *Server) createMerkleBatch(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in verificationapp.CreateMerkleBatchInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeMerkleCreationRequest(body)
		if err != nil {
			return err
		}
		return mapSigningKeyCommandError(s.merkleCreationCommands.AuthorizeMerkleCreation(ctx, a))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.merkleCreationCommands.CreateMerkleBatch(ctx, a, in)
		return http.StatusCreated, domain.MerkleBatch(v), mapSigningKeyCommandError(err)
	})
}
