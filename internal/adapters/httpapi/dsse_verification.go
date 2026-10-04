package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func decodeDSSEVerificationRequest(body []byte, raw string) (string, error) {
	if err := decodeMembershipJSON(body, &struct{}{}); err != nil {
		return "", err
	}
	if err := validateExactNonNullableObjectFields(body); err != nil {
		return "", err
	}
	id, err := verificationapp.NormalizeSigningKeyID(raw)
	return id, mapSigningKeyCommandError(err)
}

func (s *Server) verifyBuildAttestationSignature(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.dsseVerification != nil {
		var id string
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			id, err = decodeDSSEVerificationRequest(body, r.PathValue("id"))
			if err != nil {
				return err
			}
			return mapSigningKeyCommandError(s.dsseVerification.AuthorizeDSSEVerification(ctx, a, id))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.dsseVerification.VerifyDSSEAttestationSignature(ctx, a, id)
			return http.StatusOK, verificationResultFromFocused(v), mapVerificationCommandError(err)
		})
		return
	}
	// Only explicit local memory retains Ledger replay. Its current flat
	// parent/grant guard runs before replay without inspecting signed bytes.
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, body []byte) (int, any, error) {
		id, err := decodeDSSEVerificationRequest(body, r.PathValue("id"))
		if err != nil {
			return 0, nil, err
		}
		v, err := s.verification.VerifyDSSEAttestationSignature(ctx, a, id)
		return http.StatusOK, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		id, err := decodeDSSEVerificationRequest(body, r.PathValue("id"))
		if err != nil {
			return nil, err
		}
		return body, s.verification.AuthorizeDSSEVerification(r.Context(), a, id)
	})
}
