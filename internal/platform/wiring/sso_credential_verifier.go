package wiring

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/identity/saml"
	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// The platform composes protocol adapters; application code owns request state
// and never imports the XML signature library or its concrete verifier.
type ssoCredentialVerifier struct{}

func (ssoCredentialVerifier) Verify(ctx context.Context, in identityapp.CredentialVerificationRequest) (identityapp.CredentialVerificationResult, error) {
	if in.Provider.Type == "saml" {
		return (saml.Verifier{}).Verify(ctx, in)
	}
	return (app.LocalSSOCredentialVerifier{}).Verify(ctx, in)
}
