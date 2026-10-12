package app

import (
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestRoleScopesPreserveAuthenticationPolicy(t *testing.T) {
	for _, test := range []struct {
		role string
		want []string
	}{
		{role: "tenant_admin", want: []string{"*"}},
		{role: "security_engineer", want: []string{"evidence:read", "evidence:write", "security:read", "security:write", "controls:read", "controls:write", "policy:read", "policy:write", "verify:read", "report:read"}},
		{role: "release_manager", want: []string{"product:read", "project:read", "release:read", "release:write", "evidence:read", "evidence:write", "build:read", "bundle:read", "bundle:write", "verify:read", "report:read"}},
		{role: "customer_verifier", want: []string{"package:read", "bundle:read", "verify:read", "report:read"}},
		{role: "collector", want: []string{"evidence:write", "build:write", "bundle:write"}},
		{role: "unknown"},
	} {
		if got := RoleScopes(test.role); !reflect.DeepEqual(got, test.want) {
			t.Fatalf("role %q scopes=%#v, want %#v", test.role, got, test.want)
		}
	}
}

func TestProviderGroupGrantsRequireConfiguredClaimAndKnownRole(t *testing.T) {
	provider := identitydomain.SSOProvider{GroupsClaim: "groups", RoleMapping: map[string]string{"security": "security_engineer", "unknown": "not-a-role", "release": " release_manager "}}
	grants := ProviderGroupGrants(provider, []string{"security", "unknown", "release"})
	if len(grants) != 2 || grants[0].Role != "security_engineer" || grants[1].Role != "release_manager" || grants[0].ResourceType != "" || grants[1].ResourceID != "" || len(grants[0].Scopes) == 0 || len(grants[1].Scopes) == 0 {
		t.Fatalf("mapped grants=%#v", grants)
	}
	provider.GroupsClaim = ""
	if got := ProviderGroupGrants(provider, []string{"security"}); len(got) != 0 {
		t.Fatalf("unconfigured group claim granted access: %#v", got)
	}
}
