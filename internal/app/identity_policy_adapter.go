package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Stateless credential verification and assurance policy remain runtime adapters.
// The aggregate Identity service and its stateful adapters are test-only.

// LocalSSOCredentialVerifier uses configured public trust material only. It
// owns no Ledger state and makes no provider/network calls.
type LocalSSOCredentialVerifier struct{}

func (LocalSSOCredentialVerifier) Verify(_ context.Context, request identityapp.CredentialVerificationRequest) (identityapp.CredentialVerificationResult, error) {
	provider := ssoProviderFromIdentityContext(request.Provider)
	var checks []domain.VerifyCheck
	var groups []string
	var err error
	switch provider.Type {
	case "oidc":
		checks, err = verifyOIDCIDToken(provider, request.Subject, request.IDToken, request.Now)
		if err == nil {
			groups = oidcGroupsFromVerifiedToken(provider, request.IDToken)
		}
	case "saml":
		checks, err = verifySAMLAssertion(provider, request.Subject, request.SAMLAssertion, request.Now)
	default:
		return identityapp.CredentialVerificationResult{}, identityapp.ErrValidation
	}
	return identityapp.CredentialVerificationResult{Checks: verificationChecksToIdentityContext(checks), Groups: append([]string(nil), groups...)}, err
}

// LocalSSOVerificationPolicy applies the existing versioned assurance profile
// without depending on a Ledger or storage adapter.
type LocalSSOVerificationPolicy struct{}

func (LocalSSOVerificationPolicy) Assess(record identitydomain.ProviderVerification, provider identitydomain.SSOProvider, tokenSupplied bool) identitydomain.ProviderVerification {
	legacy := providerVerificationFromIdentityContext(record)
	reassessProviderVerification(&legacy, ssoProviderFromIdentityContext(provider), tokenSupplied)
	return providerVerificationToIdentityContext(legacy)
}

func (LocalSSOVerificationPolicy) ReturnsFailure(result string) bool {
	return verificationReturnsFailure(result)
}
