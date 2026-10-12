package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SSOSessionCommands interface {
	AuthorizeCreateSSOSession(context.Context, identitydomain.Actor, identityapp.CreateSSOSessionInput) error
	CreateSSOSession(context.Context, identitydomain.Actor, identityapp.CreateSSOSessionInput) (identitydomain.SSOSession, string, error)
}

func decodeSSOSessionRequest(body []byte) (identityapp.CreateSSOSessionInput, error) {
	var req struct {
		UserID     string    `json:"user_id"`
		ProviderID string    `json:"provider_id"`
		ExpiresAt  time.Time `json:"expires_at"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return identityapp.CreateSSOSessionInput{}, err
	}
	if err := validateNonNullableObjectFields(body, "user_id", "provider_id", "expires_at"); err != nil {
		return identityapp.CreateSSOSessionInput{}, err
	}
	return identityapp.CreateSSOSessionInput{UserID: req.UserID, ProviderID: req.ProviderID, ExpiresAt: req.ExpiresAt}, nil
}
func (s *Server) createDurableSSOSession(w http.ResponseWriter, r *http.Request) {
	var in identityapp.CreateSSOSessionInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeSSOSessionRequest(body)
		if err != nil {
			return err
		}
		return mapIdentityCommandError(s.ssoSessionCommands.AuthorizeCreateSSOSession(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, secret, err := s.ssoSessionCommands.CreateSSOSession(ctx, a, in)
		return http.StatusCreated, map[string]any{"session": domain.SSOSession(v), "secret": secret}, mapIdentityCommandError(err)
	})
}
