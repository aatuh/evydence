package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type failingIdentityRepository struct{ IdentityRepository }

func (failingIdentityRepository) InsertAPIKey(context.Context, domain.APIKey) error {
	return errInjectedRepositoryFailure
}

func TestCredentialExchangeCommitsVerificationAndSessionTogether(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	provider, err := ledger.CreateSSOProvider(ctx, actor, CreateSSOProviderInput{
		Name:        "Exchange OIDC",
		Type:        "oidc",
		Issuer:      "https://idp.example.test",
		ClientID:    "exchange-client",
		GroupsClaim: "groups",
		RoleMapping: map[string]string{"security": "security_engineer"},
		JWKS: map[string]any{"keys": []any{map[string]any{
			"kty": "OKP", "crv": "Ed25519", "kid": "identity-uow", "alg": "EdDSA", "x": base64.RawURLEncoding.EncodeToString(publicKey),
		}}},
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	provider, err = ledger.UpdateSSOProviderTrustMaterial(ctx, actor, provider.ID, UpdateSSOProviderTrustMaterialInput{JWKS: provider.JWKS})
	if err != nil {
		t.Fatalf("update provider trust material: %v", err)
	}
	organization, err := ledger.CreateOrganization(ctx, actor, CreateOrganizationInput{Name: "Exchange", Slug: "exchange"})
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	user, err := ledger.CreateUser(ctx, actor, CreateUserInput{OrganizationID: organization.ID, Email: "exchange@example.test", DisplayName: "Exchange User"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	inactiveUser, err := ledger.CreateUser(ctx, actor, CreateUserInput{OrganizationID: organization.ID, Email: "inactive-exchange@example.test", DisplayName: "Inactive Exchange User"})
	if err != nil {
		t.Fatalf("create inactive user: %v", err)
	}
	if deactivated, err := ledger.DeactivateUser(ctx, actor, inactiveUser.ID); err != nil || deactivated.Status != "deactivated" || deactivated.DeactivatedAt == nil {
		t.Fatalf("deactivate user result=%#v err=%v", deactivated, err)
	}
	if _, err := ledger.CreateRoleBinding(ctx, actor, CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "security_engineer", ResourceType: "tenant", ResourceID: actor.TenantID}); err != nil {
		t.Fatalf("create role binding: %v", err)
	}
	if _, err := ledger.LinkSSOIdentity(ctx, actor, LinkSSOIdentityInput{UserID: user.ID, ProviderID: provider.ID, Subject: "exchange-subject", Email: user.Email, Verified: true}); err != nil {
		t.Fatalf("link identity: %v", err)
	}
	token := signedTestIDToken(t, privateKey, "identity-uow", map[string]any{
		"iss": provider.Issuer, "aud": provider.ClientID, "sub": "exchange-subject", "email": user.Email, "email_verified": true, "groups": []string{"security"}, "exp": fixedNow().Add(time.Hour).Unix(),
	})
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before exchange failure: %v", err)
	}
	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Identity = failingIdentityRepository{IdentityRepository: repositories.Identity}
		return repositories
	}}
	verification, session, secret, err := ledger.ExchangeSSOCredential(ctx, ExchangeSSOCredentialInput{ProviderID: provider.ID, Subject: "exchange-subject", IDToken: token})
	if !errors.Is(err, errInjectedRepositoryFailure) || verification.ID != "" || session.ID != "" || secret != "" {
		t.Fatalf("failed exchange verification=%#v session=%#v secret=%q err=%v", verification, session, secret, err)
	}
	afterFailure, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after exchange failure: %v", err)
	}
	if len(afterFailure.ProviderVerifications) != len(before.ProviderVerifications) || len(afterFailure.SSOSessions) != len(before.SSOSessions) || len(afterFailure.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || len(ledger.providerVerifications) != 0 {
		t.Fatalf("failed credential exchange published state: before=%#v after=%#v", before, afterFailure)
	}

	ledger.unitOfWork = memory
	verification, session, secret, err = ledger.ExchangeSSOCredential(ctx, ExchangeSSOCredentialInput{ProviderID: provider.ID, Subject: "exchange-subject", IDToken: token})
	if err != nil {
		t.Fatalf("exchange credential: %v", err)
	}
	if verification.ID == "" || session.ID == "" || secret == "" || session.Hash != "" {
		t.Fatalf("successful exchange result verification=%#v session=%#v secret=%q", verification, session, secret)
	}
	afterSuccess, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after exchange success: %v", err)
	}
	if afterSuccess.SSOSessions[session.ID].Hash == "" || len(afterSuccess.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID])+2 {
		t.Fatalf("credential exchange did not commit verification/session/audit together: %#v", afterSuccess)
	}
	if _, ok := afterSuccess.ProviderVerifications[verification.ID]; !ok {
		t.Fatalf("credential exchange verification is missing from committed state: %#v", afterSuccess.ProviderVerifications)
	}
	sessionActor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate committed exchanged session: %v", err)
	}
	if revoked, err := ledger.RevokeCurrentSSOSession(ctx, sessionActor); err != nil || revoked.RevokedAt == nil || revoked.Hash != "" {
		t.Fatalf("revoke current session result=%#v err=%v", revoked, err)
	}
}

func (failingIdentityRepository) InsertOrganization(context.Context, domain.Organization) error {
	return errInjectedRepositoryFailure
}

func (failingIdentityRepository) InsertHumanUser(context.Context, domain.HumanUser) error {
	return errInjectedRepositoryFailure
}

func (failingIdentityRepository) DeactivateHumanUser(context.Context, domain.HumanUser) error {
	return errInjectedRepositoryFailure
}

func (failingIdentityRepository) InsertRoleBinding(context.Context, domain.RoleBinding) error {
	return errInjectedRepositoryFailure
}

func (failingIdentityRepository) InsertSSOProvider(context.Context, domain.SSOProvider) error {
	return errInjectedRepositoryFailure
}

func (failingIdentityRepository) InsertUserIdentityLink(context.Context, domain.UserIdentityLink) error {
	return errInjectedRepositoryFailure
}

func (failingIdentityRepository) InsertSSOSession(context.Context, domain.SSOSession) error {
	return errInjectedRepositoryFailure
}

func (failingIdentityRepository) RevokeSSOSession(context.Context, domain.SSOSession) error {
	return errInjectedRepositoryFailure
}

func (failingIdentityRepository) InsertCustomerPortalAccess(context.Context, domain.CustomerPortalAccess) error {
	return errInjectedRepositoryFailure
}

func (failingIdentityRepository) UpdateCustomerPortalAccess(context.Context, domain.CustomerPortalAccess, domain.CustomerPortalAccess) error {
	return errInjectedRepositoryFailure
}

type failingIdempotencyRepository struct{ IdempotencyRepository }

func (failingIdempotencyRepository) Reserve(context.Context, IdempotencyReservation) (IdempotencyReservationResult, error) {
	return IdempotencyReservationResult{}, errInjectedRepositoryFailure
}

func TestIdentityWritesCommitCredentialSecretsBeforePublication(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)

	key, keySecret, err := ledger.CreateAPIKey(ctx, actor, "automation", []string{ScopeEvidenceRead}, nil)
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	if keySecret == "" || key.Hash != "" {
		t.Fatalf("API key leaked hash or omitted secret: key=%#v secret=%q", key, keySecret)
	}
	org, err := ledger.CreateOrganization(ctx, actor, CreateOrganizationInput{Name: "Example", Slug: "example"})
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	user, err := ledger.CreateUser(ctx, actor, CreateUserInput{OrganizationID: org.ID, Email: "person@example.test", DisplayName: "Person"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := ledger.CreateRoleBinding(ctx, actor, CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "security_engineer", ResourceType: "tenant", ResourceID: actor.TenantID}); err != nil {
		t.Fatalf("create role binding: %v", err)
	}
	provider, err := ledger.CreateSSOProvider(ctx, actor, CreateSSOProviderInput{Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client"})
	if err != nil {
		t.Fatalf("create SSO provider: %v", err)
	}
	if _, err := ledger.LinkSSOIdentity(ctx, actor, LinkSSOIdentityInput{UserID: user.ID, ProviderID: provider.ID, Subject: "subject", Email: user.Email, Verified: true}); err != nil {
		t.Fatalf("link SSO identity: %v", err)
	}
	session, sessionSecret, err := ledger.CreateSSOSession(ctx, actor, CreateSSOSessionInput{UserID: user.ID, ProviderID: provider.ID, ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("create SSO session: %v", err)
	}
	if sessionSecret == "" || session.Hash != "" {
		t.Fatalf("SSO session leaked hash or omitted secret: session=%#v secret=%q", session, sessionSecret)
	}

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snapshot.APIKeys[key.ID].Hash == "" || snapshot.SSOSessions[session.ID].Hash == "" || len(snapshot.AuditEntries[actor.TenantID]) != 8 {
		t.Fatalf("identity credentials/audit were not committed together: %#v", snapshot)
	}
	ledger.customerPackages["pkg_identity_uow"] = domain.CustomerSecurityPackage{ID: "pkg_identity_uow", TenantID: actor.TenantID, Title: "Identity UOW package", State: "published", ManifestHash: "sha256:identity-uow-package", ExpiresAt: fixedNow().Add(time.Hour), SchemaVersion: domain.CustomerPackageSchemaVersion, CreatedAt: fixedNow()}
	portalAccess, portalSecret, err := ledger.CreateCustomerPortalAccess(ctx, actor, CreateCustomerPortalAccessInput{PackageID: "pkg_identity_uow", CustomerName: "Example", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("create portal access: %v", err)
	}
	if portalSecret == "" || portalAccess.Hash != "" {
		t.Fatalf("portal access leaked hash or omitted secret: access=%#v secret=%q", portalAccess, portalSecret)
	}
	if _, err := ledger.AccessCustomerPortalPackage(ctx, mutateTokenSuffix(portalSecret)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("failed portal access err=%v, want unauthorized", err)
	}
	if accessedPackage, err := ledger.AccessCustomerPortalPackage(ctx, portalSecret); err != nil || accessedPackage.ID != "pkg_identity_uow" {
		t.Fatalf("access portal package=%#v err=%v", accessedPackage, err)
	}
	if revoked, err := ledger.RevokeCustomerPortalAccess(ctx, actor, portalAccess.ID); err != nil || revoked.RevokedAt == nil || revoked.Hash != "" {
		t.Fatalf("revoke portal access result=%#v err=%v", revoked, err)
	}
	if status, _, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/test", "identity-uow", []byte(`{"kind":"identity"}`), func() (int, any, error) { return 201, map[string]any{"created": true}, nil }); err != nil || status != 201 {
		t.Fatalf("persist idempotency record status=%d err=%v", status, err)
	}
	snapshot, err = memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after portal/idempotency: %v", err)
	}
	if snapshot.CustomerPortalAccess[portalAccess.ID].Hash == "" || len(snapshot.Idempotency) != 1 {
		t.Fatalf("portal/idempotency state was not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Identity = failingIdentityRepository{IdentityRepository: repositories.Identity}
		return repositories
	}}
	before, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot before failures: %v", err)
	}
	if _, secret, err := ledger.CreateAPIKey(ctx, actor, "failed", []string{ScopeEvidenceRead}, nil); !errors.Is(err, errInjectedRepositoryFailure) || secret != "" {
		t.Fatalf("failed API key creation returned secret=%q err=%v", secret, err)
	}
	if _, secret, err := ledger.CreateSSOSession(ctx, actor, CreateSSOSessionInput{UserID: user.ID, ProviderID: provider.ID, ExpiresAt: fixedNow().Add(time.Hour)}); !errors.Is(err, errInjectedRepositoryFailure) || secret != "" {
		t.Fatalf("failed session creation returned secret=%q err=%v", secret, err)
	}
	if _, secret, err := ledger.CreateCustomerPortalAccess(ctx, actor, CreateCustomerPortalAccessInput{PackageID: "pkg_identity_uow", CustomerName: "Failed", ExpiresAt: fixedNow().Add(time.Hour)}); !errors.Is(err, errInjectedRepositoryFailure) || secret != "" {
		t.Fatalf("failed portal access creation returned secret=%q err=%v", secret, err)
	}
	if _, err := ledger.RevokeSSOSession(ctx, actor, session.ID); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed session revocation err=%v", err)
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failures: %v", err)
	}
	if len(after.APIKeys) != len(before.APIKeys) || len(after.SSOSessions) != len(before.SSOSessions) || len(after.CustomerPortalAccess) != len(before.CustomerPortalAccess) || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID]) || ledger.ssoSessions[session.ID].RevokedAt != nil {
		t.Fatalf("identity repository failure published state: before=%#v after=%#v", before, after)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Idempotency = failingIdempotencyRepository{IdempotencyRepository: repositories.Idempotency}
		return repositories
	}}
	if _, _, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/test", "idempotency-failed", []byte(`{"kind":"identity"}`), func() (int, any, error) { return 201, map[string]any{"created": true}, nil }); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed idempotency persistence err=%v", err)
	}
	afterIdempotencyFailure, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after idempotency failure: %v", err)
	}
	if len(afterIdempotencyFailure.Idempotency) != len(before.Idempotency) || len(ledger.idempotency) != len(before.Idempotency) {
		t.Fatalf("failed idempotency persistence published state: before=%#v after=%#v cache=%#v", before.Idempotency, afterIdempotencyFailure.Idempotency, ledger.idempotency)
	}

	ledger.unitOfWork = memory
	revokedAt := fixedNow()
	storedSession := after.SSOSessions[session.ID]
	storedSession.RevokedAt = &revokedAt
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error {
		return repos.Identity.RevokeSSOSession(ctx, storedSession)
	}); err != nil {
		t.Fatalf("externally revoke committed session: %v", err)
	}
	if _, err := ledger.Authenticate(ctx, sessionSecret); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale local session authenticated after durable revocation: %v", err)
	}
}

func TestMemoryIdentityRepositoryEnforcesCredentialStateTransitions(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	now := fixedNow()
	tenant := domain.Tenant{ID: "ten_memory_identity", Name: "Memory identity", CreatedAt: now}
	key := domain.APIKey{ID: "key_memory_identity", TenantID: tenant.ID, Name: "Memory key", Prefix: "evy_memory", Hash: "key-hash", Scopes: []string{ScopeEvidenceRead}, CreatedAt: now}
	product := domain.Product{ID: "prod_memory_identity", TenantID: tenant.ID, Name: "Memory product", Slug: "memory-product", CreatedAt: now}
	project := domain.Project{ID: "proj_memory_identity", TenantID: tenant.ID, ProductID: product.ID, Name: "Memory project", CreatedAt: now}
	release := domain.Release{ID: "rel_memory_identity", TenantID: tenant.ID, ProductID: product.ID, Version: "1.0.0", State: "draft", CreatedAt: now}
	organization := domain.Organization{ID: "org_memory_identity", TenantID: tenant.ID, Name: "Memory organization", Slug: "memory-organization", Status: "active", SchemaVersion: domain.OrganizationSchemaVersion, CreatedAt: now}
	user := domain.HumanUser{ID: "usr_memory_identity", TenantID: tenant.ID, OrganizationID: organization.ID, Email: "memory@example.test", DisplayName: "Memory user", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: now}
	provider := domain.SSOProvider{ID: "sso_memory_identity", TenantID: tenant.ID, Name: "Memory OIDC", Type: "oidc", Issuer: "https://memory-idp.example.test", ClientID: "memory-client", Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: now}
	session := domain.SSOSession{ID: "sess_memory_identity", TenantID: tenant.ID, UserID: user.ID, ProviderID: provider.ID, Prefix: "evysso_memory", Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: now}
	portalAccess := domain.CustomerPortalAccess{ID: "cpa_memory_identity", TenantID: tenant.ID, PackageID: "pkg_memory_identity", CustomerName: "Memory customer", Prefix: "evycp_memory", Hash: "portal-hash", ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.CustomerPortalAccessVersion, CreatedAt: now}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error {
		if err := repos.Identity.InsertTenant(ctx, tenant); err != nil {
			return err
		}
		if err := repos.Identity.InsertAPIKey(ctx, key); err != nil {
			return err
		}
		if err := repos.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
			return err
		}
		if err := repos.ReleaseCatalog.InsertProject(ctx, project); err != nil {
			return err
		}
		if err := repos.ReleaseCatalog.InsertRelease(ctx, release); err != nil {
			return err
		}
		if err := repos.Identity.InsertOrganization(ctx, organization); err != nil {
			return err
		}
		if err := repos.Identity.InsertHumanUser(ctx, user); err != nil {
			return err
		}
		if err := repos.Identity.InsertSSOProvider(ctx, provider); err != nil {
			return err
		}
		if err := repos.Identity.InsertSSOSession(ctx, session); err != nil {
			return err
		}
		return repos.Identity.InsertCustomerPortalAccess(ctx, portalAccess)
	}); err != nil {
		t.Fatalf("seed memory identity state: %v", err)
	}
	collector := domain.Collector{ID: "col_memory_identity", TenantID: tenant.ID, Name: "Memory collector", APIKeyID: key.ID}
	memory.mu.Lock()
	memory.state.Collectors[collector.ID] = collector
	memory.mu.Unlock()

	lastUsedAt := now.Add(time.Minute)
	key.LastUsedAt = &lastUsedAt
	collector.LastSeenAt = &lastUsedAt
	provider.TrustMaterialUpdatedAt = &lastUsedAt
	updatedPortalAccess := portalAccess
	updatedPortalAccess.AccessCount = 1
	updatedPortalAccess.LastAccessedAt = &lastUsedAt
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error {
		if err := repos.Identity.UpdateAPIKeyLastUsed(ctx, key); err != nil {
			return err
		}
		if err := repos.Identity.UpdateCollectorLastSeen(ctx, collector); err != nil {
			return err
		}
		if err := repos.Identity.UpdateSSOProviderTrustMaterial(ctx, provider); err != nil {
			return err
		}
		if err := repos.Identity.InsertRoleBinding(ctx, domain.RoleBinding{ID: "rbac_memory_identity", TenantID: tenant.ID, SubjectType: "user", SubjectID: user.ID, Role: "security_engineer", ResourceType: "tenant", ResourceID: tenant.ID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now}); err != nil {
			return err
		}
		if err := repos.Identity.InsertUserIdentityLink(ctx, domain.UserIdentityLink{ID: "link_memory_identity", TenantID: tenant.ID, UserID: user.ID, ProviderID: provider.ID, Subject: "memory-subject", Email: user.Email, Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: now}); err != nil {
			return err
		}
		if err := repos.Identity.InsertProviderVerification(ctx, domain.ProviderVerification{ID: "pvr_memory_identity", TenantID: tenant.ID, ProviderType: provider.Type, ProviderID: provider.ID, Subject: "memory-subject", Result: "passed", SchemaVersion: domain.ProviderVerificationVersion, CreatedAt: now}); err != nil {
			return err
		}
		return repos.Identity.UpdateCustomerPortalAccess(ctx, portalAccess, updatedPortalAccess)
	}); err != nil {
		t.Fatalf("update memory identity state: %v", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error {
		return repos.Identity.ValidateActiveSSOSession(ctx, session, now)
	}); err != nil {
		t.Fatalf("validate active memory session: %v", err)
	}
	revokedAt := now.Add(2 * time.Minute)
	session.RevokedAt = &revokedAt
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error {
		return repos.Identity.RevokeSSOSession(ctx, session)
	}); err != nil {
		t.Fatalf("revoke memory session: %v", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error {
		return repos.Identity.ValidateActiveSSOSession(ctx, session, now)
	}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("validate revoked memory session err=%v, want unauthorized", err)
	}
	user.Status = "deactivated"
	user.DeactivatedAt = &revokedAt
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error {
		return repos.Identity.DeactivateHumanUser(ctx, user)
	}); err != nil {
		t.Fatalf("deactivate memory user: %v", err)
	}
	if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error {
		return repos.Identity.UpdateCustomerPortalAccess(ctx, portalAccess, updatedPortalAccess)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale portal update err=%v, want conflict", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("memory identity snapshot: %v", err)
	}
	if snapshot.APIKeys[key.ID].LastUsedAt == nil || snapshot.Collectors[collector.ID].LastSeenAt == nil || snapshot.SSOProviders[provider.ID].TrustMaterialUpdatedAt == nil || snapshot.CustomerPortalAccess[portalAccess.ID].AccessCount != 1 || snapshot.SSOSessions[session.ID].RevokedAt == nil || snapshot.Users[user.ID].Status != "deactivated" {
		t.Fatalf("memory credential state transition was not committed: %#v", snapshot)
	}
	duplicateChecks := []struct {
		name string
		run  func(Repositories) error
	}{
		{"API key", func(repos Repositories) error { return repos.Identity.InsertAPIKey(ctx, key) }},
		{"organization", func(repos Repositories) error { return repos.Identity.InsertOrganization(ctx, organization) }},
		{"human user", func(repos Repositories) error { return repos.Identity.InsertHumanUser(ctx, user) }},
		{"SSO provider", func(repos Repositories) error { return repos.Identity.InsertSSOProvider(ctx, provider) }},
		{"identity link", func(repos Repositories) error {
			return repos.Identity.InsertUserIdentityLink(ctx, domain.UserIdentityLink{ID: "link_memory_identity_duplicate", TenantID: tenant.ID, UserID: user.ID, ProviderID: provider.ID, Subject: "memory-subject", Email: user.Email, Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: now})
		}},
		{"provider verification", func(repos Repositories) error {
			return repos.Identity.InsertProviderVerification(ctx, domain.ProviderVerification{ID: "pvr_memory_identity", TenantID: tenant.ID, ProviderType: provider.Type, ProviderID: provider.ID, Subject: "memory-subject", Result: "passed", SchemaVersion: domain.ProviderVerificationVersion, CreatedAt: now})
		}},
		{"portal access", func(repos Repositories) error { return repos.Identity.InsertCustomerPortalAccess(ctx, portalAccess) }},
	}
	for _, check := range duplicateChecks {
		if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error { return check.run(repos) }); !errors.Is(err, ErrConflict) {
			t.Errorf("duplicate %s err=%v, want conflict", check.name, err)
		}
	}
	for _, binding := range []domain.RoleBinding{
		{ID: "rbac_memory_collector", TenantID: tenant.ID, SubjectType: "collector", SubjectID: collector.ID, Role: "collector", ResourceType: "tenant", ResourceID: tenant.ID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now},
		{ID: "rbac_memory_product", TenantID: tenant.ID, SubjectType: "collector", SubjectID: collector.ID, Role: "collector", ResourceType: "product", ResourceID: product.ID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now},
		{ID: "rbac_memory_project", TenantID: tenant.ID, SubjectType: "collector", SubjectID: collector.ID, Role: "collector", ResourceType: "project", ResourceID: project.ID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now},
		{ID: "rbac_memory_release", TenantID: tenant.ID, SubjectType: "collector", SubjectID: collector.ID, Role: "collector", ResourceType: "release", ResourceID: release.ID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now},
	} {
		if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error {
			return repos.Identity.InsertRoleBinding(ctx, binding)
		}); err != nil {
			t.Fatalf("insert %s role binding: %v", binding.ResourceType, err)
		}
	}
	if !memoryRoleResourceBelongsToTenant(snapshot, tenant.ID, "", "") || memoryRoleResourceBelongsToTenant(snapshot, tenant.ID, "tenant", "ten_other") || !memoryRoleResourceBelongsToTenant(snapshot, tenant.ID, "tenant", tenant.ID) || memoryRoleResourceBelongsToTenant(snapshot, tenant.ID, "unknown", "resource") {
		t.Fatal("memory role resource helper accepted an invalid tenant scope")
	}
	if memoryRoleSubjectBelongsToTenant(snapshot, tenant.ID, "unknown", user.ID) {
		t.Fatal("memory role subject helper accepted an unknown subject type")
	}
	for _, resource := range []any{
		domain.Product{TenantID: tenant.ID},
		domain.Project{TenantID: tenant.ID},
		domain.Release{TenantID: tenant.ID},
		domain.Artifact{TenantID: tenant.ID},
		domain.EvidenceItem{TenantID: tenant.ID},
		domain.Organization{TenantID: tenant.ID},
		domain.HumanUser{TenantID: tenant.ID},
		domain.Collector{TenantID: tenant.ID},
		domain.SSOProvider{TenantID: tenant.ID},
	} {
		if memoryResourceTenantID(resource) != tenant.ID {
			t.Fatalf("resource tenant helper returned wrong tenant for %T", resource)
		}
	}
	if memoryResourceTenantID(struct{}{}) != "" {
		t.Fatal("resource tenant helper accepted an unsupported resource")
	}
}
