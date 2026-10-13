package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const samlStateCookieName = "__Host-evydence_saml_state"

type SAMLAuthenticationRequestCommands interface {
	BeginSAMLAuthentication(context.Context, identityapp.BeginSAMLAuthenticationInput) (identitydomain.SAMLAuthenticationRequest, string, error)
}
type samlAuthenticationRequestMetadata struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ProviderID    string    `json:"provider_id"`
	Delivery      string    `json:"delivery"`
	Issuer        string    `json:"issuer"`
	Audience      string    `json:"audience"`
	Recipient     string    `json:"recipient"`
	NameIDFormat  string    `json:"name_id_format"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	SchemaVersion string    `json:"schema_version"`
}

func samlRequestMetadata(v identitydomain.SAMLAuthenticationRequest) samlAuthenticationRequestMetadata {
	return samlAuthenticationRequestMetadata{ID: v.ID, TenantID: v.TenantID, ProviderID: v.ProviderID, Delivery: v.Delivery, Issuer: v.Issuer, Audience: v.Audience, Recipient: v.Recipient, NameIDFormat: v.NameIDFormat, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, SchemaVersion: v.SchemaVersion}
}
func (s *Server) beginSAMLAuthentication(w http.ResponseWriter, r *http.Request) {
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
	if err := validateExactNonNullableObjectFields(body, "provider_id", "delivery"); err != nil {
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
	request, state, err := s.samlAuthenticationRequestCommands.BeginSAMLAuthentication(r.Context(), identityapp.BeginSAMLAuthenticationInput{ProviderID: req.ProviderID, Delivery: req.Delivery})
	if err != nil {
		writeProblem(w, r, mapIdentityCommandError(err))
		return
	}
	out := map[string]any{"authentication_request": samlRequestMetadata(request)}
	if req.Delivery == "browser" {
		setSSOStateCookie(w, samlStateCookieName, state, request.ExpiresAt, false)
	} else {
		out["state_secret"] = state
	}
	writeData(w, http.StatusCreated, out)
}
