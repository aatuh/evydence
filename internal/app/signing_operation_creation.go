package app

import (
	"errors"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func mapSigningOperationContextError(err error) error {
	switch {
	case errors.Is(err, verificationapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, verificationapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, verificationapp.ErrConflict):
		return ErrConflict
	case errors.Is(err, verificationapp.ErrVerificationFailed):
		return ErrVerificationFailed
	case errors.Is(err, application.ErrUnauthorized):
		return ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return ErrForbidden
	default:
		return err
	}
}
func SigningRequestFromVerification(v verificationapp.ProviderSigningRequest) SigningRequest {
	return SigningRequest{Profile: v.Profile, TenantID: v.TenantID, ProviderID: v.ProviderID, ProviderType: v.ProviderType, ExpectedProviderType: v.ExpectedProviderType, KeyRef: v.KeyRef, SubjectType: v.SubjectType, SubjectID: v.SubjectID, PayloadHash: v.PayloadHash, CanonicalPayloadHash: v.CanonicalPayloadHash, RequestID: v.RequestID, Nonce: v.Nonce}
}
func SigningResultToVerification(v SigningResult) verificationapp.ProviderSigningResult {
	checks := make([]verificationdomain.VerifyCheck, len(v.Checks))
	for i, c := range v.Checks {
		checks[i] = verificationdomain.VerifyCheck{Name: c.Name, Result: c.Result, Detail: c.Detail}
	}
	return verificationapp.ProviderSigningResult{Signature: v.Signature, KeyID: v.KeyID, Algorithm: v.Algorithm, ProviderID: v.ProviderID, ProviderType: v.ProviderType, KeyRef: v.KeyRef, CanonicalPayloadHash: v.CanonicalPayloadHash, RequestID: v.RequestID, ProviderRequestID: v.ProviderRequestID, Checks: checks}
}

// SanitizeSigningResultMetadata keeps verified signature bytes and request
// bindings intact; only optional provider diagnostics and correlation metadata
// pass through the shared output-boundary redactor.
func SanitizeSigningResultMetadata(v SigningResult) SigningResult {
	v.KeyID = redaction.RedactString(v.KeyID)
	v.ProviderRequestID = redaction.RedactString(v.ProviderRequestID)
	v.Checks = append([]domain.VerifyCheck(nil), v.Checks...)
	for i := range v.Checks {
		v.Checks[i].Name = redaction.RedactString(v.Checks[i].Name)
		v.Checks[i].Detail = redaction.RedactString(v.Checks[i].Detail)
	}
	return v
}
