package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type RoleBindingCommands interface {
	AuthorizeCreateRoleBinding(context.Context, identitydomain.Actor, identityapp.CreateRoleBindingInput) error
	CreateRoleBinding(context.Context, identitydomain.Actor, identityapp.CreateRoleBindingInput) (identitydomain.RoleBinding, error)
}

func (s *Server) createDurableRoleBinding(w http.ResponseWriter, r *http.Request) {
	var in identityapp.CreateRoleBindingInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			SubjectType  string `json:"subject_type"`
			SubjectID    string `json:"subject_id"`
			Role         string `json:"role"`
			ResourceType string `json:"resource_type"`
			ResourceID   string `json:"resource_id"`
		}
		if err := decodeMembershipJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "subject_type", "subject_id", "role", "resource_type", "resource_id"); err != nil {
			return err
		}
		in = identityapp.CreateRoleBindingInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID, Role: req.Role, ResourceType: req.ResourceType, ResourceID: req.ResourceID}
		return mapIdentityCommandError(s.roleBindingCommands.AuthorizeCreateRoleBinding(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.roleBindingCommands.CreateRoleBinding(ctx, a, in)
		return http.StatusCreated, domain.RoleBinding(v), mapIdentityCommandError(err)
	})
}
