package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func decodeSubjectVerificationRequest(body []byte) (string, string, error) {
	var request struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	if err := decodeMembershipJSON(body, &request); err != nil {
		return "", "", err
	}
	if err := validateExactNonNullableObjectFields(body, "subject_type", "subject_id"); err != nil {
		return "", "", err
	}
	kind, id, err := verificationapp.NormalizeSubjectVerificationInput(request.SubjectType, request.SubjectID)
	return kind, id, mapVerificationCommandError(err)
}

func (s *Server) verifySubject(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.subjectVerification != nil {
		var kind, id string
		s.createDurable(w, r, func(ctx context.Context, actor domain.Actor, body []byte) error {
			var err error
			kind, id, err = decodeSubjectVerificationRequest(body)
			if err != nil {
				return err
			}
			return mapVerificationCommandError(s.subjectVerification.AuthorizeSubjectVerification(ctx, actor, kind, id))
		}, func(ctx context.Context, actor domain.Actor, _ []byte) (int, any, error) {
			result, err := s.subjectVerification.VerifySubject(ctx, actor, kind, id)
			return http.StatusOK, verificationResultFromFocused(result), mapVerificationCommandError(err)
		})
		return
	}
	// Explicit local memory only; production binds the complete closed command
	// dispatcher and durable executor, never partial-port or Ledger fallback.
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		kind, id, err := decodeSubjectVerificationRequest(body)
		if err != nil {
			return 0, nil, err
		}
		result, err := s.verification.VerifySubject(ctx, actor, kind, id)
		return http.StatusOK, result, err
	}, func(r *http.Request, actor domain.Actor, body []byte) ([]byte, error) {
		kind, id, err := decodeSubjectVerificationRequest(body)
		if err != nil {
			return nil, err
		}
		return body, s.verification.AuthorizeSubjectVerification(r.Context(), actor, kind, id)
	})
}
