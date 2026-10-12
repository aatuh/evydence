package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SSOSessionRevocationCommands interface {
	AuthorizeRevokeSSOSession(context.Context, identitydomain.Actor, string) error
	AuthorizeRevokeCurrentSSOSession(context.Context, identitydomain.Actor) error
	RevokeSSOSession(context.Context, identitydomain.Actor, string) (identitydomain.SSOSession, error)
	RevokeCurrentSSOSession(context.Context, identitydomain.Actor) (identitydomain.SSOSession, error)
}

// Session cookies are Secure and ambient authority. Mutations require a single
// HTTPS Origin matching the public request Host; proxies must preserve Host.
// Bearer authentication intentionally takes precedence over an incidental cookie.
func validateSSOCookieMutation(r *http.Request) error {
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		return nil
	}
	if len(r.CookiesNamed(ssoSessionCookieName)) == 0 {
		return nil
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 {
		return app.ErrForbidden
	}
	origin, err := url.Parse(origins[0])
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || origin.String() != origins[0] || !strings.EqualFold(origin.Host, r.Host) {
		return app.ErrForbidden
	}
	return nil
}
func (s *Server) revokeDurableSSOSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		if err := decodeSSODiscoveryRequest(body); err != nil {
			return err
		}
		return mapIdentityCommandError(s.ssoSessionRevocationCommands.AuthorizeRevokeSSOSession(ctx, a, id))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.ssoSessionRevocationCommands.RevokeSSOSession(ctx, a, id)
		return http.StatusOK, domain.SSOSession(v), mapIdentityCommandError(err)
	})
}
func (s *Server) logoutDurableSSOSession(w http.ResponseWriter, r *http.Request) {
	s.createDurableAfterCommit(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		if err := decodeSSODiscoveryRequest(body); err != nil {
			return err
		}
		return mapIdentityCommandError(s.ssoSessionRevocationCommands.AuthorizeRevokeCurrentSSOSession(ctx, a))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.ssoSessionRevocationCommands.RevokeCurrentSSOSession(ctx, a)
		return http.StatusOK, domain.SSOSession(v), mapIdentityCommandError(err)
	}, func() { clearSSOSessionCookie(w) })
}
