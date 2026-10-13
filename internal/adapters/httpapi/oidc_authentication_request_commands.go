package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const oidcStateCookieName = "__Host-evydence_oidc_state"

type OIDCAuthenticationRequestCommands interface {
	BeginOIDCAuthentication(context.Context, identityapp.BeginOIDCAuthenticationInput) (identitydomain.OIDCAuthenticationRequest, string, string, error)
}

// Public creation metadata is an explicit transport projection. The domain
// record also carries private hashes and trust bindings that never enter JSON.
type oidcAuthenticationRequestMetadata struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ProviderID    string    `json:"provider_id"`
	Delivery      string    `json:"delivery"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	SchemaVersion string    `json:"schema_version"`
}

func oidcRequestMetadata(v identitydomain.OIDCAuthenticationRequest) oidcAuthenticationRequestMetadata {
	return oidcAuthenticationRequestMetadata{ID: v.ID, TenantID: v.TenantID, ProviderID: v.ProviderID, Delivery: v.Delivery, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, SchemaVersion: v.SchemaVersion}
}

func (s *Server) beginOIDCAuthentication(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	var req struct {
		ProviderID string `json:"provider_id"`
		Delivery   string `json:"delivery"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := validateNonNullableObjectFields(body, "provider_id", "delivery"); err != nil {
		writeProblem(w, r, err)
		return
	}
	if req.Delivery == "" {
		req.Delivery = "api"
	}
	if req.Delivery != "api" && req.Delivery != "browser" {
		writeProblem(w, r, app.ErrValidation)
		return
	}
	if req.Delivery == "browser" {
		if err := validateSSOBrowserOrigin(r); err != nil {
			writeProblem(w, r, err)
			return
		}
	}
	request, state, nonce, err := s.oidcAuthenticationRequestCommands.BeginOIDCAuthentication(r.Context(), identityapp.BeginOIDCAuthenticationInput{ProviderID: req.ProviderID, Delivery: req.Delivery})
	if err != nil {
		writeProblem(w, r, mapIdentityCommandError(err))
		return
	}
	out := map[string]any{"authentication_request": oidcRequestMetadata(request), "nonce": nonce}
	if req.Delivery == "browser" {
		setOIDCStateCookie(w, state, request.ExpiresAt, false)
	} else {
		out["state_secret"] = state
	}
	writeData(w, http.StatusCreated, out)
}

func setOIDCStateCookie(w http.ResponseWriter, secret string, expires time.Time, clear bool) {
	maxAge := int(time.Until(expires).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	if clear {
		maxAge = -1
		expires = time.Unix(1, 0)
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookieName, Value: secret, Path: "/", Expires: expires.UTC(), MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func bindSSOExchangeDelivery(r *http.Request, in *identityapp.ExchangeSSOCredentialInput) error {
	if in.Delivery == "" {
		in.Delivery = "api"
	}
	if in.Delivery == "browser" {
		if err := validateSSOBrowserOrigin(r); err != nil {
			return err
		}
	}
	var cookies []*http.Cookie
	for _, line := range r.Header.Values("Cookie") {
		parsed, err := http.ParseCookie(line)
		if err != nil {
			return app.ErrUnauthorized
		}
		for _, cookie := range parsed {
			if cookie.Name == oidcStateCookieName {
				cookies = append(cookies, cookie)
			}
		}
	}
	if in.Delivery == "api" {
		if len(cookies) != 0 {
			return app.ErrUnauthorized
		}
		return nil
	}
	if in.Delivery != "browser" {
		return app.ErrValidation
	}
	if len(cookies) != 1 || cookies[0].Value == "" || in.StateSecret != "" || in.AuthenticationRequestID == "" || in.IDToken == "" || in.SAMLAssertion != "" {
		return app.ErrUnauthorized
	}
	in.StateSecret = cookies[0].Value
	return nil
}
