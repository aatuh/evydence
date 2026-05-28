package httpapi

import (
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const ssoSessionCookieName = "evydence_session"

func (s *Server) instanceAdminSnapshot(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	snapshot, err := s.ledger.InstanceAdminSnapshot(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, snapshot)
}

func (s *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		org, err := s.ledger.CreateOrganization(ctx, actor, app.CreateOrganizationInput{Name: req.Name, Slug: req.Slug})
		return http.StatusCreated, org, err
	})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID string `json:"organization_id"`
		Email          string `json:"email"`
		DisplayName    string `json:"display_name"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		user, err := s.ledger.CreateUser(ctx, actor, app.CreateUserInput{OrganizationID: req.OrganizationID, Email: req.Email, DisplayName: req.DisplayName})
		return http.StatusCreated, user, err
	})
}

func (s *Server) deactivateUser(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		user, err := s.ledger.DeactivateUser(ctx, actor, r.PathValue("id"))
		return http.StatusOK, user, err
	})
}

func (s *Server) createRoleBinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType  string `json:"subject_type"`
		SubjectID    string `json:"subject_id"`
		Role         string `json:"role"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		binding, err := s.ledger.CreateRoleBinding(ctx, actor, app.CreateRoleBindingInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID, Role: req.Role, ResourceType: req.ResourceType, ResourceID: req.ResourceID})
		return http.StatusCreated, binding, err
	})
}

func (s *Server) listRoleBindings(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	bindings, err := s.ledger.ListRoleBindings(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, bindings)
}

func (s *Server) createSSOProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                    string            `json:"name"`
		Type                    string            `json:"type"`
		Issuer                  string            `json:"issuer"`
		ClientID                string            `json:"client_id"`
		GroupsClaim             string            `json:"groups_claim"`
		RoleMapping             map[string]string `json:"role_mapping"`
		JWKS                    map[string]any    `json:"jwks"`
		SAMLSigningCertificates []string          `json:"saml_signing_certificates"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		provider, err := s.ledger.CreateSSOProvider(ctx, actor, app.CreateSSOProviderInput{Name: req.Name, Type: req.Type, Issuer: req.Issuer, ClientID: req.ClientID, GroupsClaim: req.GroupsClaim, RoleMapping: req.RoleMapping, JWKS: req.JWKS, SAMLSigningCertificates: req.SAMLSigningCertificates})
		return http.StatusCreated, provider, err
	})
}

func (s *Server) updateSSOProviderTrustMaterial(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JWKS                    map[string]any `json:"jwks"`
		SAMLSigningCertificates []string       `json:"saml_signing_certificates"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		provider, err := s.ledger.UpdateSSOProviderTrustMaterial(ctx, actor, r.PathValue("id"), app.UpdateSSOProviderTrustMaterialInput{JWKS: req.JWKS, SAMLSigningCertificates: req.SAMLSigningCertificates})
		return http.StatusOK, provider, err
	})
}

func (s *Server) refreshSSOProviderOIDCTrustMaterial(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		provider, err := s.ledger.RefreshSSOProviderOIDCTrustMaterial(ctx, actor, r.PathValue("id"))
		return http.StatusOK, provider, err
	})
}

func (s *Server) linkSSOIdentity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID     string `json:"user_id"`
		ProviderID string `json:"provider_id"`
		Subject    string `json:"subject"`
		Email      string `json:"email"`
		Verified   bool   `json:"verified"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		link, err := s.ledger.LinkSSOIdentity(ctx, actor, app.LinkSSOIdentityInput{UserID: req.UserID, ProviderID: req.ProviderID, Subject: req.Subject, Email: req.Email, Verified: req.Verified})
		return http.StatusCreated, link, err
	})
}

func (s *Server) createSSOSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID     string    `json:"user_id"`
		ProviderID string    `json:"provider_id"`
		ExpiresAt  time.Time `json:"expires_at"`
	}
	s.create(w, r, func(ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		session, secret, err := s.ledger.CreateSSOSession(ctx, actor, app.CreateSSOSessionInput{UserID: req.UserID, ProviderID: req.ProviderID, ExpiresAt: req.ExpiresAt})
		return http.StatusCreated, map[string]any{"session": session, "secret": secret}, err
	})
}

func (s *Server) exchangeSSOCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderID    string    `json:"provider_id"`
		Subject       string    `json:"subject"`
		IDToken       string    `json:"id_token"`
		SAMLAssertion string    `json:"saml_assertion"`
		ExpiresAt     time.Time `json:"expires_at"`
	}
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := decodeJSON(body, &req); err != nil {
		writeProblem(w, r, err)
		return
	}
	verification, session, secret, err := s.ledger.ExchangeSSOCredential(r.Context(), app.ExchangeSSOCredentialInput{ProviderID: req.ProviderID, Subject: req.Subject, IDToken: req.IDToken, SAMLAssertion: req.SAMLAssertion, ExpiresAt: req.ExpiresAt})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	setSSOSessionCookie(w, secret, session.ExpiresAt)
	writeData(w, http.StatusCreated, map[string]any{"verification": verification, "session": session, "secret": secret})
}

func (s *Server) revokeSSOSession(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		session, err := s.ledger.RevokeSSOSession(ctx, actor, r.PathValue("id"))
		return http.StatusOK, session, err
	})
}

func (s *Server) logoutSSOSession(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		session, err := s.ledger.RevokeCurrentSSOSession(ctx, actor)
		if err == nil {
			clearSSOSessionCookie(w)
		}
		return http.StatusOK, session, err
	})
}

func setSSOSessionCookie(w http.ResponseWriter, secret string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     ssoSessionCookieName,
		Value:    secret,
		Path:     "/v1",
		Expires:  expiresAt.UTC(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSSOSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     ssoSessionCookieName,
		Value:    "",
		Path:     "/v1",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
