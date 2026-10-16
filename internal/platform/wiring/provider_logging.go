package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/logging"
)

// Observations wrap borrowed ports only at composition. Provider ownership,
// configuration, requests, results, errors and cancellation stay unchanged.
func providerCall[Q, R any](ctx context.Context, call func(context.Context, Q) (R, error), request Q, fields logging.Fields) (R, error) {
	start := time.Now()
	response, err := call(ctx, request)
	fields.Duration = time.Since(start)
	fields.Result = logging.Succeeded
	if err != nil {
		fields.Result = logging.Failed
		fields.Retry = logging.Transient
		if errors.Is(err, app.ErrValidation) || errors.Is(err, app.ErrUnauthorized) || errors.Is(err, app.ErrForbidden) || errors.Is(err, app.ErrVerificationFailed) {
			fields.Retry = logging.Permanent
		}
	}
	logging.Emit(ctx, logging.Provider, fields)
	return response, err
}

type observedSigning struct{ app.SigningExecutor }

func observeSigningExecutor(p app.SigningExecutor) app.SigningExecutor {
	if p == nil {
		return nil
	}
	return observedSigning{p}
}
func (p observedSigning) Sign(ctx context.Context, r app.SigningRequest) (app.SigningResult, error) {
	return providerCall(ctx, p.SigningExecutor.Sign, r, logging.Fields{TenantID: r.TenantID, ResourceID: r.SubjectID, OperationID: "provider_sign"})
}

type observedOIDC struct{ app.OIDCDiscoveryClient }

func observeOIDC(p app.OIDCDiscoveryClient) app.OIDCDiscoveryClient {
	if p == nil {
		return nil
	}
	return observedOIDC{p}
}
func (p observedOIDC) FetchOIDCTrustMaterial(ctx context.Context, r app.OIDCDiscoveryRequest) (app.OIDCDiscoveryResult, error) {
	return providerCall(ctx, p.OIDCDiscoveryClient.FetchOIDCTrustMaterial, r, logging.Fields{TenantID: r.TenantID, ResourceID: r.ProviderID, OperationID: "provider_oidc_discovery"})
}

type observedIdentityProvider struct{ app.ProviderIdentityValidator }

func observeIdentityProvider(p app.ProviderIdentityValidator) app.ProviderIdentityValidator {
	if p == nil {
		return nil
	}
	return observedIdentityProvider{p}
}
func (p observedIdentityProvider) ValidateProviderIdentity(ctx context.Context, r app.ProviderIdentityValidationRequest) (app.ProviderIdentityValidationResult, error) {
	return providerCall(ctx, p.ProviderIdentityValidator.ValidateProviderIdentity, r, logging.Fields{TenantID: r.TenantID, ResourceID: r.ProviderID, OperationID: "provider_identity_validation"})
}

type observedTransparency struct{ app.TransparencyProofFetcher }

func observeTransparency(p app.TransparencyProofFetcher) app.TransparencyProofFetcher {
	if p == nil {
		return nil
	}
	return observedTransparency{p}
}
func (p observedTransparency) FetchTransparencyProof(ctx context.Context, r app.TransparencyProofRequest) (app.TransparencyProofResult, error) {
	return providerCall(ctx, p.TransparencyProofFetcher.FetchTransparencyProof, r, logging.Fields{TenantID: r.TenantID, ResourceID: r.EntryID, OperationID: "provider_transparency_fetch"})
}

type observedCosign struct{ app.CosignPolicyVerifier }

func observeCosign(p app.CosignPolicyVerifier) app.CosignPolicyVerifier {
	if p == nil {
		return nil
	}
	return observedCosign{p}
}
func (p observedCosign) VerifyCosign(ctx context.Context, r app.CosignVerificationRequest) (app.CosignVerificationReceipt, error) {
	return providerCall(ctx, p.CosignPolicyVerifier.VerifyCosign, r, logging.Fields{ResourceID: r.ArtifactDigest, OperationID: "provider_cosign_verify"})
}
