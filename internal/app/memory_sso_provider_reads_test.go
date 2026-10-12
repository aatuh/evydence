package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestMemorySSOProviderReadersDetachBoundedOwnedTrustMetadata(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		at := fixedNow()
		tx.state.SSOProviders[tenant+"-provider"] = domain.SSOProvider{ID: tenant + "-provider", TenantID: tenant, Name: "Provider", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", GroupsClaim: "groups", RoleMapping: map[string]string{"reviewers": "security_engineer"}, JWKS: map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "fixture", "n": "public-only", "e": "AQAB"}}}, TrustMaterialUpdatedAt: &at, Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: at}
	}
	reader, ok := tx.Repositories().Identity.(identityapp.SSOProviderWriteReader)
	if !ok {
		t.Fatal("memory identity lacks focused SSO provider reads")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.LockSSOProviderCreation(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadOwnedSSOProvider(t.Context(), "tenant", "tenant-provider")
	if err != nil || !reflect.DeepEqual(got, identitydomain.SSOProvider(before.SSOProviders["tenant-provider"])) {
		t.Fatal("provider reader lost complete trust metadata", got, err)
	}
	got.RoleMapping["reviewers"] = "modified"
	got.JWKS["keys"].([]any)[0].(map[string]any)["kid"] = "modified"
	*got.TrustMaterialUpdatedAt = got.TrustMaterialUpdatedAt.AddDate(1, 0, 0)
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("provider read or returned metadata mutation changed transaction state")
	}
	for _, id := range []string{"foreign-provider", "missing"} {
		if _, err := reader.ReadOwnedSSOProvider(t.Context(), "tenant", id); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign/missing provider accepted", id, err)
		}
	}
	p := tx.state.SSOProviders["tenant-provider"]
	p.Name = strings.Repeat("x", 65537)
	tx.state.SSOProviders[p.ID] = p
	if _, err := reader.ReadOwnedSSOProvider(t.Context(), "tenant", p.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized provider was truncated or accepted", err)
	}
	p = before.SSOProviders[p.ID]
	p.JWKS = map[string]any{"keys": strings.Repeat("x", 131073)}
	tx.state.SSOProviders[p.ID] = p
	if _, err := reader.ReadOwnedSSOProvider(t.Context(), "tenant", p.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized provider JSON was accepted", err)
	}
	p = before.SSOProviders[p.ID]
	p.RoleMapping = map[string]string{}
	p.JWKS = map[string]any{}
	p.SAMLSigningCertificates = []string{}
	tx.state.SSOProviders[p.ID] = p
	got, err = reader.ReadOwnedSSOProvider(t.Context(), "tenant", p.ID)
	if err != nil || got.RoleMapping != nil || got.JWKS != nil || got.SAMLSigningCertificates != nil {
		t.Fatal("empty trust projection differs from native defensive-copy representation", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.ReadOwnedSSOProvider(ctx, "tenant", p.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("provider read ignored cancellation", err)
	}
	if _, err := reader.ReadOwnedSSOProvider(t.Context(), "tenant", " provider"); !errors.Is(err, ErrValidation) {
		t.Fatal("noncanonical provider ID accepted", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := reader.LockSSOProviderCreation(t.Context(), "tenant"); !errors.Is(err, ErrConflict) {
		t.Fatal("provider read retained closed transaction", err)
	}
}

func TestMemorySSOIdentityLinkTargetsUseOwnedEmailWithoutLifecycleOrTrustReads(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		tx.state.SSOProviders[tenant+"-provider"] = domain.SSOProvider{ID: tenant + "-provider", TenantID: tenant, Status: "inactive", Name: strings.Repeat("irrelevant", 10000), JWKS: map[string]any{"private-irrelevant": make(chan int)}}
	}
	reader, ok := tx.Repositories().Identity.(identityapp.SSOIdentityLinkWriteReader)
	if !ok {
		t.Fatal("memory identity lacks focused identity-link target reads")
	}
	if err := reader.LockSSOIdentityLinkWrites(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	user := tx.state.Users["tenant-user"]
	user.DisplayName = strings.Repeat("private", 10000)
	user.OrganizationID = "foreign-org"
	tx.state.Users[user.ID] = user
	// Native linking is administrative metadata: it checks exact email and
	// tenant ownership, not login eligibility or the optional organization.
	if err := reader.ValidateSSOIdentityLinkTargets(t.Context(), "tenant", user.ID, "tenant-provider", user.Email); err != nil {
		t.Fatal("link guard read lifecycle or unrelated trust/user metadata", err)
	}
	for _, query := range []struct{ user, provider, email string }{{"foreign-user", "tenant-provider", user.Email}, {user.ID, "foreign-provider", user.Email}, {user.ID, "tenant-provider", "changed@example.test"}, {"missing", "tenant-provider", user.Email}, {user.ID, "missing", user.Email}} {
		if err := reader.ValidateSSOIdentityLinkTargets(t.Context(), "tenant", query.user, query.provider, query.email); !errors.Is(err, ErrNotFound) {
			t.Fatal("identity link accepted foreign/missing/mismatched target", query, err)
		}
	}
	if err := reader.ValidateSSOIdentityLinkTargets(t.Context(), "tenant", user.ID, "tenant-provider", " "+user.Email); !errors.Is(err, ErrValidation) {
		t.Fatal("noncanonical link email accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := reader.ValidateSSOIdentityLinkTargets(ctx, "tenant", user.ID, "tenant-provider", user.Email); !errors.Is(err, context.Canceled) {
		t.Fatal("link guard ignored cancellation", err)
	}
}
