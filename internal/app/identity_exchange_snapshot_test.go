package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestCompareSSOExchangeSnapshotMatchesOrderInsensitiveGrantSet(t *testing.T) {
	now := fixedNow()
	provider := domain.SSOProvider{
		ID: "sso_snapshot", TenantID: "ten_snapshot", Name: "Snapshot OIDC", Type: "oidc",
		Issuer: "https://idp.example.test", ClientID: "client", GroupsClaim: "groups",
		RoleMapping: map[string]string{"security": "security_engineer"},
		JWKS:        map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "key-1", "crv": "Ed25519", "x": "public"}}},
		Status:      "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: now,
	}
	user := domain.HumanUser{ID: "usr_snapshot", TenantID: provider.TenantID, Email: "user@example.test", DisplayName: "Snapshot user", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: now}
	link := domain.UserIdentityLink{ID: "link_snapshot", TenantID: provider.TenantID, UserID: user.ID, ProviderID: provider.ID, Subject: "subject-1", Email: user.Email, Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: now}
	bindings := []domain.RoleBinding{
		{ID: "rb_release", TenantID: provider.TenantID, SubjectType: "user", SubjectID: user.ID, Role: "release_manager", ResourceType: "product", ResourceID: "prod_1", SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now},
		{ID: "rb_security", TenantID: provider.TenantID, SubjectType: "user", SubjectID: user.ID, Role: "security_engineer", ResourceType: "tenant", ResourceID: provider.TenantID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now},
	}
	grants := grantsFromRoleBindings(provider.TenantID, user.ID, bindings)
	for index := range grants {
		for left, right := 0, len(grants[index].Scopes)-1; left < right; left, right = left+1, right-1 {
			grants[index].Scopes[left], grants[index].Scopes[right] = grants[index].Scopes[right], grants[index].Scopes[left]
		}
	}
	grants[0], grants[1] = grants[1], grants[0]
	grants = append(grants, grants[0])

	snapshot := SSOExchangeSnapshot{
		Provider: provider, Subject: link.Subject, IdentityLink: link, IdentityLinkFound: true,
		User: user, UserLoaded: true, UserFound: true, UserGrants: grants, UserGrantsLoaded: true,
	}
	if err := CompareSSOExchangeSnapshot(snapshot, provider, link, true, user, true, bindings); err != nil {
		t.Fatalf("compare matching snapshot: %v", err)
	}
}

func TestCompareSSOExchangeSnapshotRejectsStateDriftAndInvalidPresenceFlags(t *testing.T) {
	now := fixedNow()
	provider := domain.SSOProvider{ID: "sso_drift", TenantID: "ten_drift", Name: "Drift OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client", Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: now}
	user := domain.HumanUser{ID: "usr_drift", TenantID: provider.TenantID, Email: "user@example.test", DisplayName: "Drift user", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: now}
	link := domain.UserIdentityLink{ID: "link_drift", TenantID: provider.TenantID, UserID: user.ID, ProviderID: provider.ID, Subject: "subject-1", Email: user.Email, Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: now}
	binding := domain.RoleBinding{ID: "rb_drift", TenantID: provider.TenantID, SubjectType: "user", SubjectID: user.ID, Role: "security_engineer", ResourceType: "tenant", ResourceID: provider.TenantID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now}
	snapshot := SSOExchangeSnapshot{
		Provider: provider, Subject: link.Subject, IdentityLink: link, IdentityLinkFound: true,
		User: user, UserLoaded: true, UserFound: true,
		UserGrants: grantsFromRoleBindings(provider.TenantID, user.ID, []domain.RoleBinding{binding}), UserGrantsLoaded: true,
	}

	tests := []struct {
		name     string
		snapshot SSOExchangeSnapshot
		provider domain.SSOProvider
		link     domain.UserIdentityLink
		found    bool
		user     domain.HumanUser
		userOK   bool
		bindings []domain.RoleBinding
		want     error
	}{
		{name: "provider trust drift", snapshot: snapshot, provider: func() domain.SSOProvider {
			value := provider
			value.JWKS = map[string]any{"keys": []any{}}
			return value
		}(), link: link, found: true, user: user, userOK: true, bindings: []domain.RoleBinding{binding}, want: ErrConflict},
		{name: "previously absent link appeared", snapshot: SSOExchangeSnapshot{Provider: provider, Subject: link.Subject}, provider: provider, link: link, found: true, want: ErrConflict},
		{name: "user status drift", snapshot: snapshot, provider: provider, link: link, found: true, user: func() domain.HumanUser { value := user; value.Status = "deactivated"; return value }(), userOK: true, bindings: []domain.RoleBinding{binding}, want: ErrConflict},
		{name: "grant added", snapshot: snapshot, provider: provider, link: link, found: true, user: user, userOK: true, bindings: append([]domain.RoleBinding{binding}, domain.RoleBinding{ID: "rb_added", TenantID: provider.TenantID, SubjectType: "user", SubjectID: user.ID, Role: "release_manager", ResourceType: "tenant", ResourceID: provider.TenantID}), want: ErrConflict},
		{name: "invalid unloaded user flag", snapshot: SSOExchangeSnapshot{Provider: provider, Subject: link.Subject, IdentityLink: link, IdentityLinkFound: true, User: user, UserFound: true}, provider: provider, link: link, found: true, user: user, userOK: true, want: ErrValidation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := CompareSSOExchangeSnapshot(test.snapshot, test.provider, test.link, test.found, test.user, test.userOK, test.bindings); !errors.Is(err, test.want) {
				t.Fatalf("compare error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestMemoryIdentityRepositoryValidatesSSOExchangeSnapshotThroughCommit(t *testing.T) {
	ctx := context.Background()
	factory := NewMemoryUnitOfWorkFactory()
	now := fixedNow()
	tenant := domain.Tenant{ID: "ten_exchange_snapshot", Name: "Exchange snapshot", CreatedAt: now}
	provider := domain.SSOProvider{ID: "sso_exchange_snapshot", TenantID: tenant.ID, Name: "Exchange OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client", Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: now}
	user := domain.HumanUser{ID: "usr_exchange_snapshot", TenantID: tenant.ID, Email: "user@example.test", DisplayName: "Exchange user", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: now}
	link := domain.UserIdentityLink{ID: "link_exchange_snapshot", TenantID: tenant.ID, UserID: user.ID, ProviderID: provider.ID, Subject: "subject-existing", Email: user.Email, Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: now}
	binding := domain.RoleBinding{ID: "rb_exchange_snapshot", TenantID: tenant.ID, SubjectType: "user", SubjectID: user.ID, Role: "security_engineer", ResourceType: "tenant", ResourceID: tenant.ID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now}
	if err := ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repositories Repositories) error {
		if err := repositories.Identity.InsertTenant(ctx, tenant); err != nil {
			return err
		}
		if err := repositories.Identity.InsertHumanUser(ctx, user); err != nil {
			return err
		}
		if err := repositories.Identity.InsertSSOProvider(ctx, provider); err != nil {
			return err
		}
		if err := repositories.Identity.InsertUserIdentityLink(ctx, link); err != nil {
			return err
		}
		return repositories.Identity.InsertRoleBinding(ctx, binding)
	}); err != nil {
		t.Fatalf("seed identity state: %v", err)
	}

	validating, err := factory.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatalf("begin validating transaction: %v", err)
	}
	snapshot := SSOExchangeSnapshot{
		Provider: provider, Subject: link.Subject, IdentityLink: link, IdentityLinkFound: true,
		User: user, UserLoaded: true, UserFound: true,
		UserGrants: grantsFromRoleBindings(tenant.ID, user.ID, []domain.RoleBinding{binding}), UserGrantsLoaded: true,
	}
	if err := validating.Repositories().Identity.ValidateSSOExchangeState(ctx, snapshot); err != nil {
		t.Fatalf("validate exchange snapshot: %v", err)
	}

	concurrent, err := factory.BeginUnitOfWork(ctx)
	if err != nil {
		t.Fatalf("begin concurrent transaction: %v", err)
	}
	if err := concurrent.Repositories().Identity.InsertRoleBinding(ctx, domain.RoleBinding{ID: "rb_exchange_snapshot_added", TenantID: tenant.ID, SubjectType: "user", SubjectID: user.ID, Role: "release_manager", ResourceType: "tenant", ResourceID: tenant.ID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: now}); err != nil {
		t.Fatalf("insert concurrent grant: %v", err)
	}
	if err := concurrent.Commit(ctx); err != nil {
		t.Fatalf("commit concurrent grant: %v", err)
	}
	if err := validating.Commit(ctx); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale validated commit error = %v, want conflict", err)
	}

	if err := ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Identity.ValidateSSOExchangeState(ctx, snapshot)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale grant snapshot error = %v, want conflict", err)
	}

	absent := SSOExchangeSnapshot{Provider: provider, Subject: "subject-absent"}
	if err := ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repositories Repositories) error {
		return repositories.Identity.ValidateSSOExchangeState(ctx, absent)
	}); err != nil {
		t.Fatalf("validate absent identity link: %v", err)
	}
}
