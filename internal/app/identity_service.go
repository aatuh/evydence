package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func (l *Ledger) CreateOrganization(ctx context.Context, actor domain.Actor, in CreateOrganizationInput) (domain.Organization, error) {
	organization, err := l.identityCommands.CreateOrganization(ctx, actor, identityapp.CreateOrganizationInput{Name: in.Name, Slug: in.Slug})
	return organizationFromIdentityContext(organization), fromIdentityContextError(err)
}

func (l *Ledger) CreateUser(ctx context.Context, actor domain.Actor, in CreateUserInput) (domain.HumanUser, error) {
	user, err := l.identityCommands.CreateUser(ctx, actor, identityapp.CreateUserInput{
		OrganizationID: in.OrganizationID, Email: in.Email, DisplayName: in.DisplayName,
	})
	return humanUserFromIdentityContext(user), fromIdentityContextError(err)
}

func (l *Ledger) DeactivateUser(ctx context.Context, actor domain.Actor, id string) (domain.HumanUser, error) {
	user, err := l.identityCommands.DeactivateUser(ctx, actor, id)
	return humanUserFromIdentityContext(user), fromIdentityContextError(err)
}

func (l *Ledger) CreateRoleBinding(ctx context.Context, actor domain.Actor, in CreateRoleBindingInput) (domain.RoleBinding, error) {
	binding, err := l.identityCommands.CreateRoleBinding(ctx, actor, identityapp.CreateRoleBindingInput{
		SubjectType: in.SubjectType, SubjectID: in.SubjectID, Role: in.Role,
		ResourceType: in.ResourceType, ResourceID: in.ResourceID,
	})
	return roleBindingFromIdentityContext(binding), fromIdentityContextError(err)
}

func (l *Ledger) ListRoleBindings(ctx context.Context, actor domain.Actor) ([]domain.RoleBinding, error) {
	bindings, err := l.identityCommands.ListRoleBindings(ctx, actor)
	if err != nil {
		return nil, fromIdentityContextError(err)
	}
	result := make([]domain.RoleBinding, 0, len(bindings))
	for _, binding := range bindings {
		result = append(result, roleBindingFromIdentityContext(binding))
	}
	return result, nil
}
