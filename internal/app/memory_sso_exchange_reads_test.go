package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestMemorySSOExchangeReadsBoundedCurrentIdentityAndGrants(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Identity.(identityapp.SSOExchangeReader)
	if !ok {
		t.Fatal("memory identity lacks focused public exchange reads")
	}
	at := fixedNow()
	p := domain.SSOProvider{ID: "provider", TenantID: "tenant", Name: "Provider", Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", RoleMapping: map[string]string{"reviewers": "security_engineer"}, JWKS: map[string]any{"keys": []any{map[string]any{"kid": "public-only"}}}, TrustMaterialUpdatedAt: &at, Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: at}
	tx.state.SSOProviders[p.ID] = p
	got, err := r.SSOProviderByID(t.Context(), p.ID)
	if err != nil || !reflect.DeepEqual(got, identitydomain.SSOProvider(p)) {
		t.Fatal("public provider read lost complete owned trust metadata", got, err)
	}
	got.JWKS["keys"].([]any)[0].(map[string]any)["kid"] = "mutated"
	*got.TrustMaterialUpdatedAt = at.AddDate(1, 0, 0)
	if tx.state.SSOProviders[p.ID].JWKS["keys"].([]any)[0].(map[string]any)["kid"] != "public-only" || !tx.state.SSOProviders[p.ID].TrustMaterialUpdatedAt.Equal(at) {
		t.Fatal("provider result aliases stored metadata")
	}
	u := tx.state.Users["tenant-user"]
	u.Email = strings.Repeat("x", 3000) // Exchange reads retain historical text beyond membership-write limits.
	tx.state.Users[u.ID] = u
	user, err := r.User(t.Context(), "tenant", u.ID)
	if err != nil || !reflect.DeepEqual(user, identitydomain.HumanUser(u)) {
		t.Fatal("exchange user projection was truncated", user, err)
	}
	*user.DeactivatedAt = at.AddDate(1, 0, 0)
	if !tx.state.Users[u.ID].DeactivatedAt.Equal(at) {
		t.Fatal("exchange user timestamp aliases state")
	}
	if v, err := r.User(t.Context(), "foreign", u.ID); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, identitydomain.HumanUser{}) {
		t.Fatal("foreign user returned a partial record", v, err)
	}
	tx.state.RoleBindings["owned"] = domain.RoleBinding{ID: "owned", TenantID: "tenant", SubjectType: "user", SubjectID: u.ID, Role: "release_manager", ResourceType: "tenant", ResourceID: "tenant"}
	tx.state.RoleBindings["foreign"] = domain.RoleBinding{ID: "foreign", TenantID: "foreign", SubjectType: "user", SubjectID: u.ID, Role: "tenant_admin"}
	grants, err := r.UserGrants(t.Context(), "tenant", u.ID)
	if err != nil || len(grants) != 1 || grants[0].Role != "release_manager" || !reflect.DeepEqual(grants[0].Scopes, identityapp.RoleScopes("release_manager")) {
		t.Fatal("exchange grants leaked foreign bindings or lost scopes", grants, err)
	}
	for i := 0; i < 256; i++ {
		id := fmt.Sprint("extra-", i)
		tx.state.RoleBindings[id] = domain.RoleBinding{ID: id, TenantID: "tenant", SubjectType: "user", SubjectID: u.ID, Role: "unknown"}
	}
	if v, err := r.UserGrants(t.Context(), "tenant", u.ID); !errors.Is(err, ErrConflict) || v != nil {
		t.Fatal("excess grant rows were truncated or granted", len(v), err)
	}
	u.Email = strings.Repeat("x", 65537)
	tx.state.Users[u.ID] = u
	if v, err := r.User(t.Context(), "tenant", u.ID); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, identitydomain.HumanUser{}) {
		t.Fatal("oversized user was returned partially", v, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.SSOProviderByID(ctx, p.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, identitydomain.SSOProvider{}) {
		t.Fatal("cancelled provider read returned metadata", v, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SSOProviderByID(t.Context(), p.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction returned provider", err)
	}
}
