package httpapi

import (
	"context"
	"net/http"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type MembershipCommands interface {
	AuthorizeCreateOrganization(context.Context, identitydomain.Actor, identityapp.CreateOrganizationInput) error
	AuthorizeCreateUser(context.Context, identitydomain.Actor, identityapp.CreateUserInput) error
	AuthorizeDeactivateUser(context.Context, identitydomain.Actor, string) error
	CreateOrganization(context.Context, identitydomain.Actor, identityapp.CreateOrganizationInput) (identitydomain.Organization, error)
	CreateUser(context.Context, identitydomain.Actor, identityapp.CreateUserInput) (identitydomain.HumanUser, error)
	DeactivateUser(context.Context, identitydomain.Actor, string) (identitydomain.HumanUser, error)
}

// Reject malformed bytes before encoding/json can replace them with U+FFFD.
// Keep structural decoding and error shapes in the canonical API helper.
func decodeMembershipJSON(body []byte, out any) error {
	if !utf8.Valid(body) {
		return app.ErrValidation
	}
	return decodeJSON(body, out)
}

func (s *Server) createDurableOrganization(w http.ResponseWriter, r *http.Request) {
	var in identityapp.CreateOrganizationInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		}
		if err := decodeMembershipJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "name", "slug"); err != nil {
			return err
		}
		in = identityapp.CreateOrganizationInput{Name: req.Name, Slug: req.Slug}
		return mapIdentityCommandError(s.membershipCommands.AuthorizeCreateOrganization(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.membershipCommands.CreateOrganization(ctx, a, in)
		return http.StatusCreated, domain.Organization(v), mapIdentityCommandError(err)
	})
}
func (s *Server) createDurableUser(w http.ResponseWriter, r *http.Request) {
	var in identityapp.CreateUserInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			OrganizationID string `json:"organization_id"`
			Email          string `json:"email"`
			DisplayName    string `json:"display_name"`
		}
		if err := decodeMembershipJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "organization_id", "email", "display_name"); err != nil {
			return err
		}
		in = identityapp.CreateUserInput{OrganizationID: req.OrganizationID, Email: req.Email, DisplayName: req.DisplayName}
		return mapIdentityCommandError(s.membershipCommands.AuthorizeCreateUser(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.membershipCommands.CreateUser(ctx, a, in)
		return http.StatusCreated, domain.HumanUser(v), mapIdentityCommandError(err)
	})
}
func (s *Server) deactivateDurableUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		if err := decodeMembershipJSON(body, &struct{}{}); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body); err != nil {
			return err
		}
		return mapIdentityCommandError(s.membershipCommands.AuthorizeDeactivateUser(ctx, a, id))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.membershipCommands.DeactivateUser(ctx, a, id)
		return http.StatusOK, domain.HumanUser(v), mapIdentityCommandError(err)
	})
}
