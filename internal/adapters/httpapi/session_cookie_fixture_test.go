package httpapi

import (
	"testing"
	"time"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// CSRF tests use a real issued human session rather than placing an API key in
// the session cookie. The existing focused commands and authenticator own all
// credential, tenant, grant and transaction checks.
func fixtureSSOCookieSecret(t *testing.T, s *Server, adminSecret string) string {
	t.Helper()
	actor, err := s.authn.Authenticate(t.Context(), adminSecret)
	if err != nil {
		t.Fatal(err)
	}
	org, err := s.membershipCommands.CreateOrganization(t.Context(), actor, identityapp.CreateOrganizationInput{Name: "Cookie fixture", Slug: "cookie-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.membershipCommands.CreateUser(t.Context(), actor, identityapp.CreateUserInput{OrganizationID: org.ID, Email: "cookie-fixture@example.test", DisplayName: "Cookie fixture"})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := s.ssoProviderCommands.CreateSSOProvider(t.Context(), actor, identityapp.CreateSSOProviderInput{Name: "Cookie fixture", Type: "oidc", Issuer: "https://cookie-idp.example.test", ClientID: "cookie-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.roleBindingCommands.CreateRoleBinding(t.Context(), actor, identityapp.CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "tenant_admin", ResourceType: "tenant", ResourceID: actor.TenantID}); err != nil {
		t.Fatal(err)
	}
	_, secret, err := s.ssoSessionCommands.CreateSSOSession(t.Context(), actor, identityapp.CreateSSOSessionInput{UserID: user.ID, ProviderID: provider.ID, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return secret
}
