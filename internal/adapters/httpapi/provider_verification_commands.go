package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type ProviderVerificationCommands interface {
	AuthorizeVerifyProviderIdentity(context.Context, identitydomain.Actor, identityapp.VerifyProviderIdentityInput) error
	VerifyProviderIdentity(context.Context, identitydomain.Actor, identityapp.VerifyProviderIdentityInput) (identitydomain.ProviderVerification, error)
}

func decodeProviderVerificationRequest(body []byte) (identityapp.VerifyProviderIdentityInput, error) {
	var req struct {
		ProviderType  string `json:"provider_type"`
		ProviderID    string `json:"provider_id"`
		Subject       string `json:"subject"`
		IDToken       string `json:"id_token"`
		SAMLAssertion string `json:"saml_assertion"`
		AccessToken   string `json:"access_token"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return identityapp.VerifyProviderIdentityInput{}, err
	}
	if err := validateNonNullableObjectFields(body, "provider_type", "provider_id", "subject", "id_token", "saml_assertion", "access_token"); err != nil {
		return identityapp.VerifyProviderIdentityInput{}, err
	}
	return identityapp.VerifyProviderIdentityInput{ProviderType: req.ProviderType, ProviderID: req.ProviderID, Subject: req.Subject, IDToken: req.IDToken, SAMLAssertion: req.SAMLAssertion, AccessToken: req.AccessToken}, nil
}
func (s *Server) verifyDurableProviderIdentity(w http.ResponseWriter, r *http.Request) {
	var in identityapp.VerifyProviderIdentityInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeProviderVerificationRequest(body)
		if err != nil {
			return err
		}
		return mapIdentityCommandError(s.providerVerificationCommands.AuthorizeVerifyProviderIdentity(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.providerVerificationCommands.VerifyProviderIdentity(ctx, a, in)
		return http.StatusCreated, app.ProviderVerificationFromIdentity(v), mapIdentityCommandError(err)
	})
}
