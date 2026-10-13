package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"

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
		ProviderID              string    `json:"provider_id"`
		Subject                 string    `json:"subject"`
		IDToken                 string    `json:"id_token"`
		SAMLAssertion           string    `json:"saml_assertion"`
		ExpiresAt               time.Time `json:"expires_at"`
		AuthenticationRequestID string    `json:"authentication_request_id"`
		StateSecret             *string   `json:"state_secret"`
		Delivery                string    `json:"delivery"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return identityapp.ExchangeSSOCredentialInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "provider_id", "subject", "id_token", "saml_assertion", "expires_at", "authentication_request_id", "state_secret", "delivery"); err != nil {
		return identityapp.ExchangeSSOCredentialInput{}, err
	}
	if req.Delivery == "browser" && req.StateSecret != nil {
		return identityapp.ExchangeSSOCredentialInput{}, app.ErrUnauthorized
	}
	state := ""
	if req.StateSecret != nil {
		state = *req.StateSecret
	}
	return identityapp.ExchangeSSOCredentialInput{ProviderID: req.ProviderID, Subject: req.Subject, IDToken: req.IDToken, SAMLAssertion: req.SAMLAssertion, ExpiresAt: req.ExpiresAt, AuthenticationRequestID: req.AuthenticationRequestID, StateSecret: state, Delivery: req.Delivery}, nil
}
