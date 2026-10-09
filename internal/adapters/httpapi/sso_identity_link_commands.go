package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SSOIdentityLinkCommands interface {
	AuthorizeLinkSSOIdentity(context.Context, identitydomain.Actor, identityapp.LinkSSOIdentityInput) error
	LinkSSOIdentity(context.Context, identitydomain.Actor, identityapp.LinkSSOIdentityInput) (identitydomain.UserIdentityLink, error)
}

func decodeSSOIdentityLinkRequest(body []byte) (identityapp.LinkSSOIdentityInput, error) {
	var req struct {
		UserID     string `json:"user_id"`
		ProviderID string `json:"provider_id"`
		Subject    string `json:"subject"`
		Email      string `json:"email"`
		Verified   bool   `json:"verified"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return identityapp.LinkSSOIdentityInput{}, err
	}
	if err := validateNonNullableObjectFields(body, "user_id", "provider_id", "subject", "email", "verified"); err != nil {
		return identityapp.LinkSSOIdentityInput{}, err
	}
	return identityapp.LinkSSOIdentityInput{UserID: req.UserID, ProviderID: req.ProviderID, Subject: req.Subject, Email: req.Email, Verified: req.Verified}, nil
}
func (s *Server) linkDurableSSOIdentity(w http.ResponseWriter, r *http.Request) {
	var in identityapp.LinkSSOIdentityInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeSSOIdentityLinkRequest(body)
		if err != nil {
			return err
		}
		return mapIdentityCommandError(s.ssoIdentityLinkCommands.AuthorizeLinkSSOIdentity(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.ssoIdentityLinkCommands.LinkSSOIdentity(ctx, a, in)
		return http.StatusCreated, domain.UserIdentityLink(v), mapIdentityCommandError(err)
	})
}
