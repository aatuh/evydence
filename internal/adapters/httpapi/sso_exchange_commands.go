package httpapi

import (
	"context"
	"time"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Public exchange is not a durable idempotency replay surface. The focused
// command owns its transaction and exposes the secret only after commit.
type SSOExchangeCommands interface {
	ExchangeSSOCredential(context.Context, identityapp.ExchangeSSOCredentialInput) (identitydomain.ProviderVerification, identitydomain.SSOSession, string, error)
}

func decodeSSOExchangeRequest(body []byte) (identityapp.ExchangeSSOCredentialInput, error) {
	var req struct {
		ProviderID    string    `json:"provider_id"`
		Subject       string    `json:"subject"`
		IDToken       string    `json:"id_token"`
		SAMLAssertion string    `json:"saml_assertion"`
		ExpiresAt     time.Time `json:"expires_at"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return identityapp.ExchangeSSOCredentialInput{}, err
	}
	if err := validateNonNullableObjectFields(body, "provider_id", "subject", "id_token", "saml_assertion", "expires_at"); err != nil {
		return identityapp.ExchangeSSOCredentialInput{}, err
	}
	return identityapp.ExchangeSSOCredentialInput{ProviderID: req.ProviderID, Subject: req.Subject, IDToken: req.IDToken, SAMLAssertion: req.SAMLAssertion, ExpiresAt: req.ExpiresAt}, nil
}
