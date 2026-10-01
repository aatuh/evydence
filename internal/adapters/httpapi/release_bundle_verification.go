package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func (s *Server) verifyReleaseBundleResult(ctx context.Context, actor domain.Actor, id string) (domain.VerificationResult, error) {
	if s.releaseBundleVerification == nil {
		return s.verification.VerifySubject(ctx, actor, "release_bundle", id)
	}
	result, err := s.releaseBundleVerification.VerifyReleaseBundle(ctx, actor, id)
	return verificationResultFromFocused(result), mapVerificationCommandError(err)
}
func mapVerificationCommandError(err error) error {
	if errors.Is(err, verificationapp.ErrFullVerificationUnavailable) {
		return app.ErrFullVerificationUnavailable
	}
	if errors.Is(err, verificationapp.ErrVerificationFailed) {
		return app.ErrVerificationFailed
	}
	return mapSigningKeyCommandError(err)
}
func verificationResultFromFocused(result verificationdomain.VerificationResult) domain.VerificationResult {
	checks := make([]domain.VerifyCheck, 0, len(result.Checks))
	for _, check := range result.Checks {
		checks = append(checks, domain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	p := result.Profile
	return domain.VerificationResult{ID: result.ID, TenantID: result.TenantID, SubjectType: result.SubjectType, SubjectID: result.SubjectID, Result: result.Result.String(), Checks: checks, Profile: domain.VerificationProfile{ID: p.ID, Version: p.Version, RequiredChecks: p.RequiredChecks, TrustMaterial: p.TrustMaterial, IdentityPolicy: p.IdentityPolicy, TransparencyProof: p.TransparencyProof, PayloadScope: p.PayloadScope, PayloadDigest: p.PayloadDigest, Limitations: p.Limitations}, Limitations: result.Limitations, SchemaVersion: result.SchemaVersion, VerifiedAt: result.VerifiedAt}
}
