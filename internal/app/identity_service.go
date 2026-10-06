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

func (l *Ledger) CreateSSOProvider(ctx context.Context, actor domain.Actor, in CreateSSOProviderInput) (domain.SSOProvider, error) {
	provider, err := l.identityCommands.CreateSSOProvider(ctx, actor, identityapp.CreateSSOProviderInput{
		Name: in.Name, Type: in.Type, Issuer: in.Issuer, ClientID: in.ClientID, GroupsClaim: in.GroupsClaim,
		RoleMapping: cloneStringMap(in.RoleMapping), JWKS: cloneIdentityAnyMap(in.JWKS),
		SAMLSigningCertificates: append([]string(nil), in.SAMLSigningCertificates...),
	})
	return ssoProviderFromIdentityContext(provider), fromIdentityContextError(err)
}

func (l *Ledger) UpdateSSOProviderTrustMaterial(ctx context.Context, actor domain.Actor, id string, in UpdateSSOProviderTrustMaterialInput) (domain.SSOProvider, error) {
	provider, err := l.identityCommands.UpdateSSOProviderTrustMaterial(ctx, actor, id, identityapp.UpdateSSOProviderTrustMaterialInput{
		JWKS: cloneIdentityAnyMap(in.JWKS), SAMLSigningCertificates: append([]string(nil), in.SAMLSigningCertificates...),
	})
	return ssoProviderFromIdentityContext(provider), fromIdentityContextError(err)
}

func (l *Ledger) RefreshSSOProviderOIDCTrustMaterial(ctx context.Context, actor domain.Actor, id string) (domain.SSOProvider, error) {
	provider, err := l.identityCommands.RefreshSSOProviderOIDCTrustMaterial(ctx, actor, id)
	return ssoProviderFromIdentityContext(provider), fromIdentityContextError(err)
}

func (l *Ledger) LinkSSOIdentity(ctx context.Context, actor domain.Actor, in LinkSSOIdentityInput) (domain.UserIdentityLink, error) {
	link, err := l.identityCommands.LinkSSOIdentity(ctx, actor, identityapp.LinkSSOIdentityInput{
		UserID: in.UserID, ProviderID: in.ProviderID, Subject: in.Subject, Email: in.Email, Verified: in.Verified,
	})
	return userIdentityLinkFromIdentityContext(link), fromIdentityContextError(err)
}

func (l *Ledger) CreateSSOSession(ctx context.Context, actor domain.Actor, in CreateSSOSessionInput) (domain.SSOSession, string, error) {
	session, secret, err := l.identityCommands.CreateSSOSession(ctx, actor, identityapp.CreateSSOSessionInput{
		UserID: in.UserID, ProviderID: in.ProviderID, ExpiresAt: in.ExpiresAt,
	})
	return ssoSessionFromIdentityContext(session), secret, fromIdentityContextError(err)
}

func (l *Ledger) ExchangeSSOCredential(ctx context.Context, in ExchangeSSOCredentialInput) (domain.ProviderVerification, domain.SSOSession, string, error) {
	verification, session, secret, err := l.identityCommands.ExchangeSSOCredential(ctx, identityapp.ExchangeSSOCredentialInput{
		ProviderID: in.ProviderID, Subject: in.Subject, IDToken: in.IDToken,
		SAMLAssertion: in.SAMLAssertion, ExpiresAt: in.ExpiresAt,
	})
	return providerVerificationFromIdentityContext(verification), ssoSessionFromIdentityContext(session), secret, fromIdentityContextError(err)
}

func (l *Ledger) RevokeSSOSession(ctx context.Context, actor domain.Actor, id string) (domain.SSOSession, error) {
	session, err := l.identityCommands.RevokeSSOSession(ctx, actor, id)
	return ssoSessionFromIdentityContext(session), fromIdentityContextError(err)
}

func (l *Ledger) RevokeCurrentSSOSession(ctx context.Context, actor domain.Actor) (domain.SSOSession, error) {
	session, err := l.identityCommands.RevokeCurrentSSOSession(ctx, actor)
	return ssoSessionFromIdentityContext(session), fromIdentityContextError(err)
}
