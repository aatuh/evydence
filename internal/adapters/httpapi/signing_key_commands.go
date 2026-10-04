package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func decodeSigningRotationRequest(body []byte) (string, error) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return "", err
	}
	if err := validateExactNonNullableObjectFields(body, "reason"); err != nil {
		return "", err
	}
	reason, err := verificationapp.NormalizeSigningKeyReason(req.Reason)
	return reason, mapSigningKeyCommandError(err)
}

func decodeSigningRevocationRequest(body []byte) (verificationapp.SigningKeyRevocationInput, error) {
	var req struct {
		Reason                   string `json:"reason"`
		Semantics                string `json:"semantics"`
		HistoricalValidityPolicy string `json:"historical_validity_policy"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return verificationapp.SigningKeyRevocationInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "reason", "semantics", "historical_validity_policy"); err != nil {
		return verificationapp.SigningKeyRevocationInput{}, err
	}
	in, err := verificationapp.NormalizeSigningKeyRevocationInput(verificationapp.SigningKeyRevocationInput{Reason: req.Reason, Semantics: req.Semantics, HistoricalValidityPolicy: req.HistoricalValidityPolicy})
	return in, mapSigningKeyCommandError(err)
}

func (s *Server) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.signingKeyCommands != nil {
		var reason string
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			reason, err = decodeSigningRotationRequest(body)
			if err != nil {
				return err
			}
			return mapSigningKeyCommandError(s.signingKeyCommands.AuthorizeSigningKeyRotation(ctx, a))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			key, err := s.signingKeyCommands.RotateSigningKey(ctx, a, reason)
			return http.StatusCreated, signingKeyFromQuery(key), mapSigningKeyCommandError(err)
		})
		return
	}
	// Explicit local memory shares the bounds/current policy but is nondurable.
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, body []byte) (int, any, error) {
		reason, err := decodeSigningRotationRequest(body)
		if err != nil {
			return 0, nil, err
		}
		key, err := s.verification.RotateSigningKey(ctx, a, reason)
		return http.StatusCreated, key, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		if _, err := decodeSigningRotationRequest(body); err != nil {
			return nil, err
		}
		return body, mapSigningKeyCommandError(application.AuthorizeTenantWideScope(r.Context(), a, app.ScopeKeysAdmin))
	})
}

func (s *Server) revokeSigningKey(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	id, err := verificationapp.NormalizeSigningKeyID(r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, mapSigningKeyCommandError(err))
		return
	}
	if s.signingKeyCommands != nil {
		var in verificationapp.SigningKeyRevocationInput
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeSigningRevocationRequest(body)
			if err != nil {
				return err
			}
			return mapSigningKeyCommandError(s.signingKeyCommands.AuthorizeSigningKeyRevocation(ctx, a, id))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			key, err := s.signingKeyCommands.RevokeSigningKey(ctx, a, id, in)
			return http.StatusOK, signingKeyFromQuery(key), mapSigningKeyCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, body []byte) (int, any, error) {
		in, err := decodeSigningRevocationRequest(body)
		if err != nil {
			return 0, nil, err
		}
		key, err := s.verification.RevokeSigningKeyWithPolicy(ctx, a, id, app.SigningKeyRevocationInput(in))
		return http.StatusOK, key, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		if _, err := decodeSigningRevocationRequest(body); err != nil {
			return nil, err
		}
		return body, s.verification.AuthorizeSigningKeyRevocation(r.Context(), a, id)
	})
}

func mapSigningKeyCommandError(err error) error {
	switch {
	case errors.Is(err, verificationapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, verificationapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, verificationapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	default:
		return err
	}
}
