package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPackageCatalogVisibilityKeepsPackageAndProjectAuthoritySeparate(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{"package:read"}, ResourceGrants: []identitydomain.ResourceGrant{
		{ResourceType: "product", ResourceID: "b", Scopes: []string{"package:read"}}, {ResourceType: "product", ResourceID: "a", Scopes: []string{"*"}}, {ResourceType: "product", ResourceID: "a", Scopes: []string{"admin"}},
		{ResourceType: "release", ResourceID: "release", Scopes: []string{"package:read"}}, {ResourceType: "project", ResourceID: "project", Scopes: []string{"*"}},
		{ResourceType: "customer_security_package", ResourceID: "package-b", Scopes: []string{"package:read"}}, {ResourceType: "customer_security_package", ResourceID: "package-a", Scopes: []string{"*"}}, {ResourceType: "customer_security_package", ResourceID: "package-a", Scopes: []string{"admin"}},
		{ResourceType: "product", ResourceID: "wrong-scope", Scopes: []string{"package:write"}}, {ResourceType: "customer_security_package", ResourceID: "write-only", Scopes: []string{"package:write"}}, {ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}},
	}}
	for _, action := range []Action{"answer_library_entries.read", "portal_access.read"} {
		want := Visibility{TenantID: "tenant", ProductIDs: []string{"a", "b"}, ReleaseIDs: []string{"release"}}
		if action == "portal_access.read" {
			want.CustomerPackageIDs = []string{"package-a", "package-b"}
		}
		visibility, err := ReadVisibility(t.Context(), actor, action)
		if err != nil || !reflect.DeepEqual(visibility, want) {
			t.Fatal("catalog filter boundary", action, visibility, want, err)
		}
		a := actor
		a.ResourceGrants = nil
		visibility, err = ReadVisibility(t.Context(), a, action)
		if err != nil || !reflect.DeepEqual(visibility, Visibility{TenantID: "tenant"}) {
			t.Fatal("revoked catalog authority", action, visibility, err)
		}
		a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}
		visibility, err = ReadVisibility(t.Context(), a, action)
		if err != nil || !reflect.DeepEqual(visibility, Visibility{TenantID: "tenant", TenantWide: true}) {
			t.Fatal("tenant catalog authority", visibility, err)
		}
		a.Scopes = []string{"package:write"}
		visibility, err = ReadVisibility(t.Context(), a, action)
		if !errors.Is(err, ErrForbidden) || !reflect.DeepEqual(visibility, Visibility{}) {
			t.Fatal("write capability leaked read filter", visibility, err)
		}
	}
}
