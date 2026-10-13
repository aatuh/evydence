package app

import (
	"context"
	"strings"
	"time"

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
	var nonce string
	var issuedAt, expiresAt time.Time
	switch provider.Type {
	case "oidc":
		checks, err = verifyOIDCIDToken(provider, request.Subject, request.IDToken, request.Now)
		if err == nil {
			groups = oidcGroupsFromVerifiedToken(provider, request.IDToken)
			parts := strings.Split(request.IDToken, ".")
			body, decodeErr := decodeOIDCSegment(parts[1])
			var claims oidcJWTClaims
			if decodeErr != nil || decodeOIDCObject(body, &claims) != nil {
				return identityapp.CredentialVerificationResult{}, identityapp.ErrVerificationFailed
			}
			nonce = claims.Nonce
			issuedAt = time.Unix(claims.IssuedAt, 0).UTC()
			expiresAt = time.Unix(claims.ExpiresAt, 0).UTC()
		}
	case "saml":
		checks, err = verifySAMLAssertion(provider, request.Subject, request.SAMLAssertion, request.Now)
	default:
		return identityapp.CredentialVerificationResult{}, identityapp.ErrValidation
	}
	return identityapp.CredentialVerificationResult{Checks: verificationChecksToIdentityContext(checks), Groups: append([]string(nil), groups...), Nonce: nonce, IssuedAt: issuedAt, ExpiresAt: expiresAt}, err
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
