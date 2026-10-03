package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestCreateOrganizationAuthorizesBeforeReadingAndCommitsAudit(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	organization, err := fixture.service.CreateOrganization(context.Background(), fixture.actor, CreateOrganizationInput{Name: " Example ", Slug: " example "})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if organization.ID != "org_1" || organization.Name != "Example" || organization.Slug != "example" || organization.TenantID != fixture.actor.TenantID {
		t.Fatalf("organization = %#v", organization)
	}
	if stored := fixture.transactions.state.organizations[organization.ID]; stored.ID == "" {
		t.Fatalf("organization was not committed: %#v", fixture.transactions.state)
	}
	if len(fixture.transactions.state.audit) != 1 || fixture.transactions.state.audit[0].EntryType != "organization.created" {
		t.Fatalf("audit = %#v", fixture.transactions.state.audit)
	}
	if request := fixture.authorizer.requests[0]; request.Scope != ScopeIdentityAdmin || !request.ScopeOnly || !request.TenantWide {
		t.Fatalf("authorization request = %#v", request)
	}

	denied := newIdentityServiceFixture(t)
	denied.authorizer.err = ErrForbidden
	if _, err := denied.service.CreateOrganization(context.Background(), denied.actor, CreateOrganizationInput{Name: "Example", Slug: "example"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateOrganization denied error = %v", err)
	}
	if denied.reader.calls != 0 || denied.transactions.commits != 0 {
		t.Fatalf("denied command reached reader/transaction: reader=%d commits=%d", denied.reader.calls, denied.transactions.commits)
	}
}

func TestCreateOrganizationAuditFailureRollsBackRecord(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.transactions.auditErr = errIdentityCommit
	if _, err := fixture.service.CreateOrganization(context.Background(), fixture.actor, CreateOrganizationInput{Name: "Example", Slug: "example"}); !errors.Is(err, errIdentityCommit) {
		t.Fatalf("CreateOrganization error = %v", err)
	}
	if len(fixture.transactions.state.organizations) != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("state = %#v rollbacks=%d", fixture.transactions.state, fixture.transactions.rollbacks)
	}
}

func TestCreateUserRejectsForeignOrganizationBeforeTransaction(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.organizations = []identitydomain.Organization{{ID: "org_foreign", TenantID: "ten_2"}}
	if _, err := fixture.service.CreateUser(context.Background(), fixture.actor, CreateUserInput{OrganizationID: "org_foreign", Email: "person@example.test", DisplayName: "Person"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CreateUser error = %v, want not found", err)
	}
	if fixture.transactions.commits != 0 {
		t.Fatalf("commits = %d", fixture.transactions.commits)
	}
}

func TestCreateRoleBindingRejectsForeignGrantTarget(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.targets.subjectErr = ErrNotFound
	if _, err := fixture.service.CreateRoleBinding(context.Background(), fixture.actor, CreateRoleBindingInput{SubjectType: "user", SubjectID: "usr_foreign", Role: "security_engineer", ResourceType: "tenant", ResourceID: fixture.actor.TenantID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CreateRoleBinding error = %v, want not found", err)
	}
	if fixture.targets.subjectCalls != 1 || fixture.targets.resourceCalls != 0 || fixture.transactions.commits != 0 {
		t.Fatalf("target calls subject=%d resource=%d commits=%d", fixture.targets.subjectCalls, fixture.targets.resourceCalls, fixture.transactions.commits)
	}
}

func TestListRoleBindingsFiltersForeignTenantRecords(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.roleBindings = []identitydomain.RoleBinding{
		{ID: "rb_2", TenantID: fixture.actor.TenantID},
		{ID: "rb_foreign", TenantID: "ten_2"},
		{ID: "rb_1", TenantID: fixture.actor.TenantID},
	}
	bindings, err := fixture.service.ListRoleBindings(context.Background(), fixture.actor)
	if err != nil {
		t.Fatalf("ListRoleBindings: %v", err)
	}
	if len(bindings) != 2 || bindings[0].ID != "rb_1" || bindings[1].ID != "rb_2" {
		t.Fatalf("bindings = %#v", bindings)
	}
}

func TestUpdateSSOProviderTrustMaterialIsTenantScopedAndAudited(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID, Type: "oidc", Issuer: "https://idp.example.test", Status: "active"}}
	fixture.transactions.state.providers["sso_1"] = cloneSSOProvider(fixture.reader.providers[0])
	fixture.trust.jwks = map[string]any{"keys": []any{map[string]any{"kid": "one"}}}
	provider, err := fixture.service.UpdateSSOProviderTrustMaterial(context.Background(), fixture.actor, "sso_1", UpdateSSOProviderTrustMaterialInput{JWKS: map[string]any{"keys": []any{"raw"}}})
	if err != nil {
		t.Fatalf("UpdateSSOProviderTrustMaterial: %v", err)
	}
	if provider.TrustMaterialUpdatedAt == nil || provider.TrustMaterialUpdatedAt.UTC() != fixture.now || len(provider.JWKS) == 0 {
		t.Fatalf("provider = %#v", provider)
	}
	if fixture.hasher.calls != 1 || len(fixture.transactions.state.audit) != 1 || fixture.transactions.state.audit[0].PayloadHash != "sha256:trust" {
		t.Fatalf("hasher calls=%d audit=%#v", fixture.hasher.calls, fixture.transactions.state.audit)
	}

	foreign := newIdentityServiceFixture(t)
	foreign.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: "ten_2", Type: "oidc"}}
	foreign.trust.jwks = fixture.trust.jwks
	if _, err := foreign.service.UpdateSSOProviderTrustMaterial(context.Background(), foreign.actor, "sso_1", UpdateSSOProviderTrustMaterialInput{JWKS: fixture.trust.jwks}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign update error = %v", err)
	}
}

func TestUpdateSSOProviderTrustMaterialRejectsConcurrentTrustMaterialChange(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	readAt := fixture.now.Add(-2 * time.Hour)
	stale := identitydomain.SSOProvider{
		ID:                     "sso_1",
		TenantID:               fixture.actor.TenantID,
		Type:                   "oidc",
		Issuer:                 "https://idp.example.test",
		Status:                 "active",
		JWKS:                   map[string]any{"keys": []any{map[string]any{"kid": "stale"}}},
		TrustMaterialUpdatedAt: &readAt,
	}
	fixture.reader.providers = []identitydomain.SSOProvider{stale}
	concurrent := cloneSSOProvider(stale)
	changedAt := fixture.now.Add(-time.Hour)
	concurrent.JWKS = map[string]any{"keys": []any{map[string]any{"kid": "concurrent"}}}
	concurrent.TrustMaterialUpdatedAt = &changedAt
	fixture.transactions.state.providers[concurrent.ID] = concurrent
	fixture.trust.jwks = map[string]any{"keys": []any{map[string]any{"kid": "requested"}}}

	provider, err := fixture.service.UpdateSSOProviderTrustMaterial(context.Background(), fixture.actor, stale.ID, UpdateSSOProviderTrustMaterialInput{JWKS: fixture.trust.jwks})
	if !errors.Is(err, ErrConflict) || provider.ID != "" {
		t.Fatalf("provider=%#v err=%v, want conflict", provider, err)
	}
	stored := fixture.transactions.state.providers[concurrent.ID]
	if stored.TrustMaterialUpdatedAt == nil || !stored.TrustMaterialUpdatedAt.Equal(changedAt) || !strings.Contains(fmt.Sprint(stored.JWKS), "concurrent") {
		t.Fatalf("concurrent provider overwritten: %#v", stored)
	}
	if len(fixture.transactions.state.audit) != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("audit=%#v commits=%d rollbacks=%d", fixture.transactions.state.audit, fixture.transactions.commits, fixture.transactions.rollbacks)
	}
}

func TestRefreshOIDCTrustRejectsIssuerMismatchWithoutWrite(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID, Type: "oidc", Issuer: "https://idp.example.test", Status: "active"}}
	fixture.discovery.result = OIDCDiscoveryResult{Issuer: "https://other.example.test", JWKS: map[string]any{"keys": []any{"raw"}}}
	if _, err := fixture.service.RefreshSSOProviderOIDCTrustMaterial(context.Background(), fixture.actor, "sso_1"); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("RefreshSSOProviderOIDCTrustMaterial error = %v", err)
	}
	if fixture.transactions.commits != 0 {
		t.Fatalf("commits = %d", fixture.transactions.commits)
	}
}

func TestRefreshOIDCTrustRejectsConcurrentTrustMaterialChange(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	readAt := fixture.now.Add(-2 * time.Hour)
	stale := identitydomain.SSOProvider{
		ID:                     "sso_1",
		TenantID:               fixture.actor.TenantID,
		Type:                   "oidc",
		Issuer:                 "https://idp.example.test",
		ClientID:               "client",
		Status:                 "active",
		JWKS:                   map[string]any{"keys": []any{map[string]any{"kid": "stale"}}},
		TrustMaterialUpdatedAt: &readAt,
	}
	fixture.reader.providers = []identitydomain.SSOProvider{stale}
	changedAt := fixture.now.Add(-time.Hour)
	concurrent := cloneSSOProvider(stale)
	concurrent.JWKS = map[string]any{"keys": []any{map[string]any{"kid": "concurrent"}}}
	concurrent.TrustMaterialUpdatedAt = &changedAt
	fixture.transactions.state.providers[concurrent.ID] = concurrent
	fixture.discovery.result = OIDCDiscoveryResult{Issuer: stale.Issuer, JWKS: map[string]any{"keys": []any{map[string]any{"kid": "discovered"}}}}
	fixture.trust.jwks = fixture.discovery.result.JWKS

	provider, err := fixture.service.RefreshSSOProviderOIDCTrustMaterial(context.Background(), fixture.actor, stale.ID)
	if !errors.Is(err, ErrConflict) || provider.ID != "" {
		t.Fatalf("provider=%#v err=%v, want conflict", provider, err)
	}
	stored := fixture.transactions.state.providers[concurrent.ID]
	if stored.TrustMaterialUpdatedAt == nil || !stored.TrustMaterialUpdatedAt.Equal(changedAt) || !strings.Contains(fmt.Sprint(stored.JWKS), "concurrent") {
		t.Fatalf("concurrent provider overwritten: %#v", stored)
	}
	if len(fixture.transactions.state.audit) != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("audit=%#v commits=%d rollbacks=%d", fixture.transactions.state.audit, fixture.transactions.commits, fixture.transactions.rollbacks)
	}
}

func TestLinkSSOIdentityRequiresSameTenantMatchingEmail(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.users = []identitydomain.HumanUser{{ID: "usr_1", TenantID: fixture.actor.TenantID, Email: "person@example.test", Status: "active"}}
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID}}
	if _, err := fixture.service.LinkSSOIdentity(context.Background(), fixture.actor, LinkSSOIdentityInput{UserID: "usr_1", ProviderID: "sso_1", Subject: "subject", Email: "other@example.test", Verified: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LinkSSOIdentity error = %v, want not found", err)
	}
	if fixture.transactions.commits != 0 {
		t.Fatalf("commits = %d", fixture.transactions.commits)
	}
}

func TestCreateSSOSessionReturnsSecretOnlyAfterCommit(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.users = []identitydomain.HumanUser{{ID: "usr_1", TenantID: fixture.actor.TenantID, Email: "person@example.test", Status: "active"}}
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID, Status: "active"}}
	fixture.transactions.err = errIdentityCommit
	session, secret, err := fixture.service.CreateSSOSession(context.Background(), fixture.actor, CreateSSOSessionInput{UserID: "usr_1", ProviderID: "sso_1", ExpiresAt: fixture.now.Add(time.Hour)})
	if !errors.Is(err, errIdentityCommit) || session.ID != "" || secret != "" {
		t.Fatalf("session=%#v secret=%q err=%v", session, secret, err)
	}
	if len(fixture.transactions.state.sessions) != 0 {
		t.Fatalf("sessions = %#v", fixture.transactions.state.sessions)
	}
}

func TestCreateSSOSessionRejectsExpiredInputAndAuditFailureWithoutSecret(t *testing.T) {
	expired := newIdentityServiceFixture(t)
	if session, secret, err := expired.service.CreateSSOSession(context.Background(), expired.actor, CreateSSOSessionInput{UserID: "usr_1", ProviderID: "sso_1", ExpiresAt: expired.now}); !errors.Is(err, ErrValidation) || session.ID != "" || secret != "" {
		t.Fatalf("expired session=%#v secret=%q err=%v", session, secret, err)
	}
	if expired.reader.calls != 0 || expired.transactions.commits != 0 {
		t.Fatalf("expired request reached reader/transaction: calls=%d commits=%d", expired.reader.calls, expired.transactions.commits)
	}

	auditFailure := newIdentityServiceFixture(t)
	auditFailure.reader.users = []identitydomain.HumanUser{{ID: "usr_1", TenantID: auditFailure.actor.TenantID, Status: "active"}}
	auditFailure.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: auditFailure.actor.TenantID}}
	auditFailure.transactions.auditErr = errIdentityCommit
	session, secret, err := auditFailure.service.CreateSSOSession(context.Background(), auditFailure.actor, CreateSSOSessionInput{UserID: "usr_1", ProviderID: "sso_1", ExpiresAt: auditFailure.now.Add(time.Hour)})
	if !errors.Is(err, errIdentityCommit) || session.ID != "" || secret != "" {
		t.Fatalf("audit failure session=%#v secret=%q err=%v", session, secret, err)
	}
	if len(auditFailure.transactions.state.sessions) != 0 || len(auditFailure.transactions.state.audit) != 0 {
		t.Fatalf("audit failure state = %#v", auditFailure.transactions.state)
	}
}

func TestCreateSSOSessionCredentialFailureDoesNotStartTransaction(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.users = []identitydomain.HumanUser{{ID: "usr_1", TenantID: fixture.actor.TenantID, Status: "active"}}
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID}}
	fixture.sessionCredentials.err = errIdentityCommit
	session, secret, err := fixture.service.CreateSSOSession(context.Background(), fixture.actor, CreateSSOSessionInput{UserID: "usr_1", ProviderID: "sso_1", ExpiresAt: fixture.now.Add(time.Hour)})
	if !errors.Is(err, errIdentityCommit) || session.ID != "" || secret != "" {
		t.Fatalf("session=%#v secret=%q err=%v", session, secret, err)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("transactions = %#v", fixture.transactions)
	}
}

func TestExchangeSSOCredentialCommitsVerificationSessionAndAuditsTogether(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID, Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client", GroupsClaim: "groups", Status: "active"}}
	fixture.reader.links = []identitydomain.UserIdentityLink{{ID: "link_1", TenantID: fixture.actor.TenantID, ProviderID: "sso_1", UserID: "usr_1", Subject: "subject", Verified: true}}
	fixture.reader.users = []identitydomain.HumanUser{{ID: "usr_1", TenantID: fixture.actor.TenantID, Email: "person@example.test", Status: "active"}}
	fixture.reader.userGrants = []identitydomain.ResourceGrant{{Role: "security_engineer", Scopes: []string{"evidence:read"}}}
	fixture.verifier.result = CredentialVerificationResult{Checks: []identitydomain.VerificationCheck{{Name: "signature", Result: "passed"}}, Groups: []string{"security"}}
	fixture.sessionGrants.grants = []identitydomain.ResourceGrant{{Role: "security_engineer", Scopes: []string{"evidence:write"}}}

	verification, session, secret, err := fixture.service.ExchangeSSOCredential(context.Background(), ExchangeSSOCredentialInput{ProviderID: "sso_1", Subject: "subject", IDToken: "raw-id-token"})
	if err != nil {
		t.Fatalf("ExchangeSSOCredential: %v", err)
	}
	if verification.Result != "passed" || session.ID != "sess_1" || session.Hash != "" || secret != "evysso_secret" {
		t.Fatalf("verification=%#v session=%#v secret=%q", verification, session, secret)
	}
	stored := fixture.transactions.state.sessions[session.ID]
	if stored.Hash != "session-hash" || len(fixture.transactions.state.verifications) != 1 || len(fixture.transactions.state.audit) != 2 {
		t.Fatalf("state = %#v", fixture.transactions.state)
	}
	if strings.Contains(fmt.Sprintf("%#v", fixture.transactions.state), "raw-id-token") {
		t.Fatalf("raw credential retained in state: %#v", fixture.transactions.state)
	}
}

func TestExchangeSSOCredentialPersistsFailedVerificationWithoutSession(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID, Type: "oidc", Status: "active"}}
	fixture.verifier.result = CredentialVerificationResult{Checks: []identitydomain.VerificationCheck{{Name: "signature", Result: "passed"}}}
	verification, session, secret, err := fixture.service.ExchangeSSOCredential(context.Background(), ExchangeSSOCredentialInput{ProviderID: "sso_1", Subject: "missing-link", IDToken: "raw-id-token"})
	if !errors.Is(err, ErrVerificationFailed) || verification.Result != "failed" || session.ID != "" || secret != "" {
		t.Fatalf("verification=%#v session=%#v secret=%q err=%v", verification, session, secret, err)
	}
	if len(fixture.transactions.state.verifications) != 1 || len(fixture.transactions.state.sessions) != 0 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("state = %#v", fixture.transactions.state)
	}
}

func TestExchangeSSOCredentialAuditFailureReturnsNoRecordOrSecret(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID, Type: "oidc", Status: "active"}}
	fixture.verifier.result = CredentialVerificationResult{Checks: []identitydomain.VerificationCheck{{Name: "signature", Result: "failed"}}}
	fixture.transactions.auditErr = errIdentityCommit
	verification, session, secret, err := fixture.service.ExchangeSSOCredential(context.Background(), ExchangeSSOCredentialInput{ProviderID: "sso_1", Subject: "subject", IDToken: "raw-id-token"})
	if !errors.Is(err, errIdentityCommit) || verification.ID != "" || session.ID != "" || secret != "" {
		t.Fatalf("verification=%#v session=%#v secret=%q err=%v", verification, session, secret, err)
	}
	if len(fixture.transactions.state.verifications) != 0 || len(fixture.transactions.state.audit) != 0 {
		t.Fatalf("state = %#v", fixture.transactions.state)
	}
}

func TestExchangeSSOCredentialPersistsAuthorizationGrantFailure(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID, Type: "oidc", Status: "active"}}
	fixture.reader.links = []identitydomain.UserIdentityLink{{ID: "link_1", TenantID: fixture.actor.TenantID, ProviderID: "sso_1", UserID: "usr_1", Subject: "subject", Verified: true}}
	fixture.reader.users = []identitydomain.HumanUser{{ID: "usr_1", TenantID: fixture.actor.TenantID, Status: "active"}}
	fixture.verifier.result = CredentialVerificationResult{Checks: []identitydomain.VerificationCheck{{Name: "signature", Result: "passed"}}}
	verification, session, secret, err := fixture.service.ExchangeSSOCredential(context.Background(), ExchangeSSOCredentialInput{ProviderID: "sso_1", Subject: "subject", IDToken: "raw-id-token"})
	if !errors.Is(err, ErrForbidden) || verification.Result != "failed" || session.ID != "" || secret != "" {
		t.Fatalf("verification=%#v session=%#v secret=%q err=%v", verification, session, secret, err)
	}
	if len(fixture.transactions.state.verifications) != 1 || len(fixture.transactions.state.sessions) != 0 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("state = %#v", fixture.transactions.state)
	}
}

func TestExchangeSSOCredentialSanitizesVerifierFailure(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID, Type: "oidc", Status: "active"}}
	fixture.verifier.err = errors.New("provider rejected raw-id-token with database detail")
	verification, _, _, err := fixture.service.ExchangeSSOCredential(context.Background(), ExchangeSSOCredentialInput{ProviderID: "sso_1", Subject: "subject", IDToken: "raw-id-token"})
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("ExchangeSSOCredential error = %v", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", verification), "raw-id-token") || strings.Contains(fmt.Sprintf("%#v", verification), "database detail") {
		t.Fatalf("verification leaked verifier detail: %#v", verification)
	}
}

func TestExchangeSSOCredentialRedactsRawCredentialFromVerifierChecks(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID, Type: "oidc", Status: "active"}}
	fixture.verifier.result = CredentialVerificationResult{Checks: []identitydomain.VerificationCheck{{Name: "signature", Result: "failed", Detail: "rejected raw-id-token"}}}
	verification, _, _, err := fixture.service.ExchangeSSOCredential(context.Background(), ExchangeSSOCredentialInput{ProviderID: "sso_1", Subject: "subject", IDToken: "raw-id-token"})
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("ExchangeSSOCredential error = %v", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", verification), "raw-id-token") || strings.Contains(fmt.Sprintf("%#v", fixture.transactions.state), "raw-id-token") {
		t.Fatalf("raw credential retained: verification=%#v state=%#v", verification, fixture.transactions.state)
	}
}

func TestExchangeSSOCredentialDoesNotRetainCredentialAsSubjectOrGroup(t *testing.T) {
	subject := newIdentityServiceFixture(t)
	verification, session, secret, err := subject.service.ExchangeSSOCredential(context.Background(), ExchangeSSOCredentialInput{ProviderID: "sso_1", Subject: "subject-raw-id-token-value", IDToken: "raw-id-token"})
	if !errors.Is(err, ErrValidation) || verification.ID != "" || session.ID != "" || secret != "" {
		t.Fatalf("subject verification=%#v session=%#v secret=%q err=%v", verification, session, secret, err)
	}
	if subject.reader.calls != 0 || subject.transactions.commits != 0 {
		t.Fatalf("subject request reached reader/transaction: calls=%d commits=%d", subject.reader.calls, subject.transactions.commits)
	}

	group := newIdentityServiceFixture(t)
	configureSuccessfulExchange(group)
	group.verifier.result.Groups = []string{"team", "raw-id-token"}
	_, issued, _, err := group.service.ExchangeSSOCredential(context.Background(), ExchangeSSOCredentialInput{ProviderID: "sso_1", Subject: "subject", IDToken: "raw-id-token"})
	if err != nil {
		t.Fatalf("ExchangeSSOCredential: %v", err)
	}
	if len(issued.Groups) != 1 || issued.Groups[0] != "team" || strings.Contains(fmt.Sprintf("%#v", group.transactions.state), "raw-id-token") {
		t.Fatalf("issued=%#v state=%#v", issued, group.transactions.state)
	}
}

func TestExchangeSSOCredentialRejectsStaleTransactionState(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*identityServiceFixture)
		assert    func(*testing.T, SSOExchangeSnapshot)
	}{
		{
			name: "provider changed",
			assert: func(t *testing.T, snapshot SSOExchangeSnapshot) {
				t.Helper()
				if snapshot.Provider.ID != "sso_1" || snapshot.Provider.Status != "active" {
					t.Fatalf("provider snapshot = %#v", snapshot.Provider)
				}
			},
		},
		{
			name: "link changed",
			configure: func(fixture *identityServiceFixture) {
				fixture.reader.links = nil
			},
			assert: func(t *testing.T, snapshot SSOExchangeSnapshot) {
				t.Helper()
				if snapshot.Subject != "subject" || snapshot.IdentityLinkFound || snapshot.IdentityLink.ID != "" {
					t.Fatalf("identity-link snapshot = %#v", snapshot)
				}
			},
		},
		{
			name: "user changed",
			configure: func(fixture *identityServiceFixture) {
				fixture.reader.users[0].Status = "deactivated"
			},
			assert: func(t *testing.T, snapshot SSOExchangeSnapshot) {
				t.Helper()
				if !snapshot.UserLoaded || !snapshot.UserFound || snapshot.User.ID != "usr_1" || snapshot.User.Status != "deactivated" {
					t.Fatalf("user snapshot = %#v", snapshot)
				}
			},
		},
		{
			name: "missing user appeared",
			configure: func(fixture *identityServiceFixture) {
				fixture.reader.users = nil
			},
			assert: func(t *testing.T, snapshot SSOExchangeSnapshot) {
				t.Helper()
				if !snapshot.UserLoaded || snapshot.UserFound || snapshot.IdentityLink.UserID != "usr_1" {
					t.Fatalf("missing-user snapshot = %#v", snapshot)
				}
			},
		},
		{
			name: "grant changed",
			configure: func(fixture *identityServiceFixture) {
				fixture.reader.userGrants = nil
			},
			assert: func(t *testing.T, snapshot SSOExchangeSnapshot) {
				t.Helper()
				if !snapshot.UserGrantsLoaded || len(snapshot.UserGrants) != 0 {
					t.Fatalf("grant snapshot = %#v", snapshot)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIdentityServiceFixture(t)
			configureSuccessfulExchange(fixture)
			if test.configure != nil {
				test.configure(fixture)
			}
			fixture.transactions.validateExchange = func(snapshot SSOExchangeSnapshot) error {
				test.assert(t, snapshot)
				return ErrConflict
			}

			verification, session, secret, err := fixture.service.ExchangeSSOCredential(context.Background(), ExchangeSSOCredentialInput{ProviderID: "sso_1", Subject: "subject", IDToken: "raw-id-token"})
			if !errors.Is(err, ErrConflict) || verification.ID != "" || session.ID != "" || secret != "" {
				t.Fatalf("verification=%#v session=%#v secret=%q err=%v", verification, session, secret, err)
			}
			if fixture.transactions.exchangeValidations != 1 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || len(fixture.transactions.state.verifications) != 0 || len(fixture.transactions.state.sessions) != 0 {
				t.Fatalf("transactions = %#v state = %#v", fixture.transactions, fixture.transactions.state)
			}
		})
	}
}

func TestRevokeSSOSessionEnforcesTenantAndSelfOwnership(t *testing.T) {
	foreign := newIdentityServiceFixture(t)
	foreign.reader.sessions = []identitydomain.SSOSession{{ID: "sess_1", TenantID: "ten_2", UserID: "usr_1", Prefix: "evysso", Hash: "hash", ExpiresAt: foreign.now.Add(time.Hour)}}
	if _, err := foreign.service.RevokeSSOSession(context.Background(), foreign.actor, "sess_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign revoke error = %v", err)
	}

	self := newIdentityServiceFixture(t)
	self.reader.sessions = []identitydomain.SSOSession{{ID: "sess_1", TenantID: self.actor.TenantID, UserID: "usr_1", Prefix: "evysso", Hash: "hash", ExpiresAt: self.now.Add(time.Hour)}}
	actor := identitydomain.Actor{TenantID: self.actor.TenantID, UserID: "usr_other", SessionID: "sess_1"}
	if _, err := self.service.RevokeCurrentSSOSession(context.Background(), actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched self revoke error = %v", err)
	}
	if self.transactions.commits != 0 {
		t.Fatalf("commits = %d", self.transactions.commits)
	}
}

func TestHumanIdentityAdminCanRevokeAnotherUsersSession(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.sessions = []identitydomain.SSOSession{{ID: "sess_1", TenantID: fixture.actor.TenantID, UserID: "usr_1", Prefix: "evysso", Hash: "hash", ExpiresAt: fixture.now.Add(time.Hour)}}
	admin := identitydomain.Actor{TenantID: fixture.actor.TenantID, UserID: "usr_admin", SessionID: "sess_admin", Scopes: []string{ScopeIdentityAdmin}}
	session, err := fixture.service.RevokeSSOSession(context.Background(), admin, "sess_1")
	if err != nil {
		t.Fatalf("RevokeSSOSession: %v", err)
	}
	if session.RevokedAt == nil || session.Hash != "" || fixture.transactions.state.sessions[session.ID].Hash != "hash" {
		t.Fatalf("session=%#v stored=%#v", session, fixture.transactions.state.sessions[session.ID])
	}
}

func TestRevokeSSOSessionRejectsAlreadyRevokedRecordWithoutTransaction(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	revokedAt := fixture.now.Add(-time.Minute)
	fixture.reader.sessions = []identitydomain.SSOSession{{ID: "sess_1", TenantID: fixture.actor.TenantID, UserID: "usr_1", Prefix: "evysso", Hash: "hash", ExpiresAt: fixture.now.Add(time.Hour), RevokedAt: &revokedAt}}
	if _, err := fixture.service.RevokeSSOSession(context.Background(), fixture.actor, "sess_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("RevokeSSOSession error = %v, want conflict", err)
	}
	if fixture.transactions.commits != 0 {
		t.Fatalf("commits = %d", fixture.transactions.commits)
	}
}

func configureSuccessfulExchange(fixture *identityServiceFixture) {
	fixture.reader.providers = []identitydomain.SSOProvider{{ID: "sso_1", TenantID: fixture.actor.TenantID, Type: "oidc", Status: "active"}}
	fixture.reader.links = []identitydomain.UserIdentityLink{{ID: "link_1", TenantID: fixture.actor.TenantID, ProviderID: "sso_1", UserID: "usr_1", Subject: "subject", Verified: true}}
	fixture.reader.users = []identitydomain.HumanUser{{ID: "usr_1", TenantID: fixture.actor.TenantID, Status: "active"}}
	fixture.reader.userGrants = []identitydomain.ResourceGrant{{Role: "security_engineer", Scopes: []string{"evidence:read"}}}
	fixture.verifier.result = CredentialVerificationResult{Checks: []identitydomain.VerificationCheck{{Name: "signature", Result: "passed"}}}
}
