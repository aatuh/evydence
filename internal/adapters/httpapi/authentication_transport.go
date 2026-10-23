package httpapi

import (
	"errors"
	"net/http"
	"strings"

	authshared "github.com/aatuh/api-toolkit/v3/middleware/auth/shared"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// Explicit Authorization values own the credential boundary, even when invalid.
// Cookie credentials are reserved for a single human SSO session.
func httpAuthenticationCredential(r *http.Request) (string, bool, error) {
	headers := r.Header.Values("Authorization")
	if len(headers) != 0 {
		if len(headers) != 1 {
			return "", false, app.ErrUnauthorized
		}
		token, present, err := authshared.ParseBearerToken(headers[0])
		if err != nil || !present {
			return "", false, app.ErrUnauthorized
		}
		return token, false, nil
	}
	cookies := r.CookiesNamed(ssoSessionCookieName)
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0].Value, "evysso_") || cookies[0].Value != strings.TrimSpace(cookies[0].Value) {
		return "", len(cookies) != 0, app.ErrUnauthorized
	}
	return cookies[0].Value, true, nil
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (domain.Actor, bool) {
	lease, allowed := s.reserveFailureAttempt(w, r, "credential")
	if !allowed {
		return domain.Actor{}, false
	}
	failed := true
	if lease != nil {
		defer func() { lease.finish(failed) }()
	}
	actor, authenticated := s.authenticateCredential(w, r)
	if !authenticated {
		return domain.Actor{}, false
	}
	failed = false
	if !s.allowExpensiveTenantRequest(actor, r) {
		writeProblem(w, r, app.ErrRateLimited)
		return domain.Actor{}, false
	}
	recordLogTenant(r.Context(), actor.TenantID)
	return actor, true
}

func (s *Server) authenticateCredential(w http.ResponseWriter, r *http.Request) (domain.Actor, bool) {
	// Reject cross-origin mutations before verifying or clearing ambient cookies.
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && len(r.Header.Values("Authorization")) == 0 && len(r.CookiesNamed(ssoSessionCookieName)) != 0 {
		if err := validateSSOCookieMutation(r); err != nil {
			writeProblem(w, r, err)
			return domain.Actor{}, false
		}
	}
	token, cookie, err := httpAuthenticationCredential(r)
	if err != nil {
		if cookie {
			clearSSOSessionCookie(w)
		}
		writeProblem(w, r, app.ErrUnauthorized)
		return domain.Actor{}, false
	}
	actor, err := s.authn.Authenticate(r.Context(), token)
	if err == nil && cookie && (actor.SessionID == "" || actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "") {
		err = app.ErrUnauthorized
	}
	if err != nil {
		switch {
		case errors.Is(err, identityapp.ErrUnauthorized), errors.Is(err, app.ErrUnauthorized):
			err = app.ErrUnauthorized
			if cookie {
				clearSSOSessionCookie(w)
			}
		case errors.Is(err, identityapp.ErrForbidden):
			err = app.ErrForbidden
		}
		writeProblem(w, r, err)
		return domain.Actor{}, false
	}
	recordLogTenant(r.Context(), actor.TenantID)
	return actor, true
}
