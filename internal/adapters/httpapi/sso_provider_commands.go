package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SSOProviderCommands interface {
	AuthorizeCreateSSOProvider(context.Context, identitydomain.Actor, identityapp.CreateSSOProviderInput) error
	CreateSSOProvider(context.Context, identitydomain.Actor, identityapp.CreateSSOProviderInput) (identitydomain.SSOProvider, error)
	AuthorizeUpdateSSOProviderTrustMaterial(context.Context, identitydomain.Actor, string, identityapp.UpdateSSOProviderTrustMaterialInput) error
	UpdateSSOProviderTrustMaterial(context.Context, identitydomain.Actor, string, identityapp.UpdateSSOProviderTrustMaterialInput) (identitydomain.SSOProvider, error)
}

func decodeSSOTrustRequest(body []byte) (identityapp.UpdateSSOProviderTrustMaterialInput, error) {
	var req struct {
		JWKS         map[string]any `json:"jwks"`
		Certificates []*string      `json:"saml_signing_certificates"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return identityapp.UpdateSSOProviderTrustMaterialInput{}, err
	}
	if err := validateNonNullableObjectFields(body, "jwks", "saml_signing_certificates"); err != nil {
		return identityapp.UpdateSSOProviderTrustMaterialInput{}, err
	}
	in := identityapp.UpdateSSOProviderTrustMaterialInput{JWKS: req.JWKS}
	for _, cert := range req.Certificates {
		if cert == nil {
			return identityapp.UpdateSSOProviderTrustMaterialInput{}, app.ErrValidation
		}
		in.SAMLSigningCertificates = append(in.SAMLSigningCertificates, *cert)
	}
	return in, nil
}
func (s *Server) updateDurableSSOTrustMaterial(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in identityapp.UpdateSSOProviderTrustMaterialInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeSSOTrustRequest(body)
		if err != nil {
			return err
		}
		return mapIdentityCommandError(s.ssoProviderCommands.AuthorizeUpdateSSOProviderTrustMaterial(ctx, a, id, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.ssoProviderCommands.UpdateSSOProviderTrustMaterial(ctx, a, id, in)
		return http.StatusOK, domain.SSOProvider(v), mapIdentityCommandError(err)
	})
}

func decodeSSOProviderRequest(body []byte) (identityapp.CreateSSOProviderInput, error) {
	var req struct {
		Name                    string             `json:"name"`
		Type                    string             `json:"type"`
		Issuer                  string             `json:"issuer"`
		ClientID                string             `json:"client_id"`
		GroupsClaim             string             `json:"groups_claim"`
		RoleMapping             map[string]*string `json:"role_mapping"`
		JWKS                    map[string]any     `json:"jwks"`
		SAMLSigningCertificates []*string          `json:"saml_signing_certificates"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return identityapp.CreateSSOProviderInput{}, err
	}
	if err := validateNonNullableObjectFields(body, "name", "type", "issuer", "client_id", "groups_claim", "role_mapping", "jwks", "saml_signing_certificates"); err != nil {
		return identityapp.CreateSSOProviderInput{}, err
	}
	in := identityapp.CreateSSOProviderInput{Name: req.Name, Type: req.Type, Issuer: req.Issuer, ClientID: req.ClientID, GroupsClaim: req.GroupsClaim, JWKS: req.JWKS}
	if req.RoleMapping != nil {
		in.RoleMapping = make(map[string]string, len(req.RoleMapping))
		for group, role := range req.RoleMapping {
			if role == nil {
				return identityapp.CreateSSOProviderInput{}, app.ErrValidation
			}
			in.RoleMapping[group] = *role
		}
	}
	for _, cert := range req.SAMLSigningCertificates {
		if cert == nil {
			return identityapp.CreateSSOProviderInput{}, app.ErrValidation
		}
		in.SAMLSigningCertificates = append(in.SAMLSigningCertificates, *cert)
	}
	return in, nil
}
func (s *Server) createDurableSSOProvider(w http.ResponseWriter, r *http.Request) {
	var in identityapp.CreateSSOProviderInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeSSOProviderRequest(body)
		if err != nil {
			return err
		}
		return mapIdentityCommandError(s.ssoProviderCommands.AuthorizeCreateSSOProvider(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.ssoProviderCommands.CreateSSOProvider(ctx, a, in)
		return http.StatusCreated, domain.SSOProvider(v), mapIdentityCommandError(err)
	})
}
