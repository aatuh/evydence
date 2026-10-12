package app

import (
	"strings"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// RoleScopes is the single role-to-scope mapping used by Ledger compatibility
// and database-backed authentication projections. Unknown roles grant nothing.
func RoleScopes(role string) []string {
	switch role {
	case "tenant_admin":
		return []string{"*"}
	case "security_engineer":
		return []string{
			"evidence:read", "evidence:write", "security:read", "security:write",
			"controls:read", "controls:write", "policy:read", "policy:write",
			"verify:read", "report:read",
		}
	case "release_manager":
		return []string{
			"product:read", "project:read", "release:read", "release:write",
			"evidence:read", "evidence:write", "build:read", "bundle:read",
			"bundle:write", "verify:read", "report:read",
		}
	case "customer_verifier":
		return []string{"package:read", "bundle:read", "verify:read", "report:read"}
	case "collector":
		return []string{"evidence:write", "build:write", "bundle:write"}
	default:
		return nil
	}
}

// ProviderGroupGrants returns session-scoped tenant grants only when a provider
// has an explicit group claim and a known mapped role.
func ProviderGroupGrants(provider identitydomain.SSOProvider, groups []string) []identitydomain.ResourceGrant {
	if provider.GroupsClaim == "" || len(provider.RoleMapping) == 0 || len(groups) == 0 {
		return nil
	}
	grants := make([]identitydomain.ResourceGrant, 0, len(groups))
	for _, group := range groups {
		role := strings.TrimSpace(provider.RoleMapping[group])
		scopes := RoleScopes(role)
		if len(scopes) == 0 {
			continue
		}
		grants = append(grants, identitydomain.ResourceGrant{Role: role, Scopes: scopes})
	}
	return grants
}
