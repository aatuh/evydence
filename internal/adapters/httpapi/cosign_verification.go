package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func decodeCosignVerificationRequest(body []byte, id string) (verificationapp.VerifyCosignInput, error) {
	var req struct {
		ExpectedIdentity string `json:"expected_identity"`
		ExpectedIssuer   string `json:"expected_issuer"`
		Mode             string `json:"mode"`
		Offline          bool   `json:"offline"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return verificationapp.VerifyCosignInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "mode", "offline", "expected_identity", "expected_issuer"); err != nil {
		return verificationapp.VerifyCosignInput{}, err
	}
	in, err := verificationapp.NormalizeVerifyCosignInput(verificationapp.VerifyCosignInput{ArtifactSignatureID: id, ExpectedIdentity: req.ExpectedIdentity, ExpectedIssuer: req.ExpectedIssuer, Mode: verificationapp.CosignVerificationMode(req.Mode), Offline: req.Offline})
	return in, mapSigningKeyCommandError(err)
}

func (s *Server) verifyCosignSignature(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.cosignVerification != nil {
		var in verificationapp.VerifyCosignInput
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeCosignVerificationRequest(body, r.PathValue("id"))
			if err != nil {
				return err
			}
			return mapSigningKeyCommandError(s.cosignVerification.AuthorizeCosignVerification(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.cosignVerification.VerifyCosign(ctx, a, in)
			return http.StatusOK, cosignVerificationFromFocused(v), mapVerificationCommandError(err)
		})
		return
	}
	// Explicit local memory remains nondurable; a saved receipt cannot replace
	// current tenant-level verification authority.
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, body []byte) (int, any, error) {
		in, err := decodeCosignVerificationRequest(body, r.PathValue("id"))
		if err != nil {
			return 0, nil, err
		}
		v, err := s.verification.VerifyCosignSignature(ctx, a, app.VerifyCosignInput{ArtifactSignatureID: in.ArtifactSignatureID, ExpectedIdentity: in.ExpectedIdentity, ExpectedIssuer: in.ExpectedIssuer, Mode: app.CosignVerificationMode(in.Mode), Offline: in.Offline})
		return http.StatusOK, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		if _, err := decodeCosignVerificationRequest(body, r.PathValue("id")); err != nil {
			return nil, err
		}
		return body, mapSigningKeyCommandError(application.AuthorizeTenantWideScope(r.Context(), a, app.ScopeVerifyRead))
	})
}

func cosignVerificationFromFocused(r verificationdomain.CosignVerification) domain.CosignVerification {
	return domain.CosignVerificationFromContextModel(r)
}
