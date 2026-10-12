package authz

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestCollectorCredentialPolicyBindsExactKeyTenantIdentityAndCapabilities(t *testing.T) {
	binding := CollectorCredentialBinding{ID: "collector", TenantID: "tenant", APIKeyID: "key", Status: "active", AllowedScopes: []string{"evidence:write", "source:read", "source:read", "unknown-inert"}}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write", "evidence:write"}}
	before := slices.Clone(binding.AllowedScopes)
	if err := CheckCollectorCredentialBinding(actor, binding); err != nil || !reflect.DeepEqual(before, binding.AllowedScopes) {
		t.Fatal("narrower duplicate-issued capability changed", err)
	}
	actor.CollectorID = "collector"
	if err := CheckCollectorCredentialBinding(actor, binding); err != nil {
		t.Fatal("matching authenticated collector identity", err)
	}
	for _, edit := range []func(*identitydomain.Actor){
		func(a *identitydomain.Actor) { a.CollectorID = "foreign" }, func(a *identitydomain.Actor) { a.TenantID = "foreign" }, func(a *identitydomain.Actor) { a.KeyID = "foreign" }, func(a *identitydomain.Actor) { a.KeyID = "" }, func(a *identitydomain.Actor) { a.UserID = "human" }, func(a *identitydomain.Actor) { a.SessionID = "session" }, func(a *identitydomain.Actor) { a.Scopes = []string{"admin"} }, func(a *identitydomain.Actor) { a.Scopes = []string{"*"} }, func(a *identitydomain.Actor) { a.Scopes = []string{"instance:admin"} }, func(a *identitydomain.Actor) { a.Scopes = []string{" evidence:write "} },
	} {
		bad := actor
		edit(&bad)
		bad.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}
		if err := CheckCollectorCredentialBinding(bad, binding); !errors.Is(err, ErrForbidden) {
			t.Fatal("claim/grant expanded collector binding", err)
		}
	}
	for _, edit := range []func(*CollectorCredentialBinding){func(b *CollectorCredentialBinding) { b.Status = "disabled" }, func(b *CollectorCredentialBinding) { b.Status = "revoked" }, func(b *CollectorCredentialBinding) { b.Status = " active " }, func(b *CollectorCredentialBinding) { b.ID = "" }, func(b *CollectorCredentialBinding) { b.ID = "foreign" }, func(b *CollectorCredentialBinding) { b.AllowedScopes = nil }, func(b *CollectorCredentialBinding) { b.AllowedScopes = []string{"", "evidence:write"} }, func(b *CollectorCredentialBinding) { b.AllowedScopes = []string{" evidence:write "} }, func(b *CollectorCredentialBinding) { b.AllowedScopes = make([]string, 1025) }} {
		bad := binding
		edit(&bad)
		if err := CheckCollectorCredentialBinding(actor, bad); !errors.Is(err, ErrForbidden) {
			t.Fatal("invalid/currently foreign collector binding", err)
		}
	}
}
