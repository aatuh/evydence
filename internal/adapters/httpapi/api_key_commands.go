package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type APIKeyCommands interface {
	AuthorizeCreateAPIKey(context.Context, identitydomain.Actor, identityapp.CreateAPIKeyInput) error
	CreateAPIKey(context.Context, identitydomain.Actor, identityapp.CreateAPIKeyInput) (identitydomain.APIKey, string, error)
}

func mapIdentityCommandError(err error) error {
	switch {
	case errors.Is(err, identityapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, identityapp.ErrUnauthorized), errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, identityapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, identityapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, identityapp.ErrVerificationFailed):
		return app.ErrVerificationFailed
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
func (s *Server) createDurableAPIKey(w http.ResponseWriter, r *http.Request) {
	var in identityapp.CreateAPIKeyInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			Name      string     `json:"name"`
			Scopes    []string   `json:"scopes"`
			ExpiresAt *time.Time `json:"expires_at"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "name", "scopes", "expires_at"); err != nil {
			return err
		}
		if err := validateNonNullableArrayItems(body, "scopes"); err != nil {
			return err
		}
		in = identityapp.CreateAPIKeyInput{Name: req.Name, Scopes: req.Scopes, ExpiresAt: req.ExpiresAt}
		return mapIdentityCommandError(s.apiKeyCommands.AuthorizeCreateAPIKey(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		key, secret, err := s.apiKeyCommands.CreateAPIKey(ctx, a, in)
		return http.StatusCreated, map[string]any{"api_key": domain.APIKey(key), "secret": secret}, mapIdentityCommandError(err)
	})
}
