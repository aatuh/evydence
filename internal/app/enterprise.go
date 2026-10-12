package app

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func validRoleSubject(value string) bool {
	return value == "user" || value == "collector"
}

func validRole(value string) bool {
	switch value {
	case "tenant_admin", "security_engineer", "release_manager", "customer_verifier", "collector":
		return true
	default:
		return false
	}
}

func resourceGrantsForProviderGroups(provider domain.SSOProvider, groups []string) []domain.ResourceGrant {
	return identityapp.ProviderGroupGrants(ssoProviderToIdentityContext(provider), groups)
}

func scopesFromResourceGrants(grants []domain.ResourceGrant) []string {
	scopes := map[string]struct{}{}
	for _, grant := range grants {
		for _, scope := range grant.Scopes {
			scopes[scope] = struct{}{}
		}
	}
	out := make([]string, 0, len(scopes))
	for scope := range scopes {
		out = append(out, scope)
	}
	return sortedStrings(out)
}

func humanSessionActor(actor domain.Actor) bool {
	return actor.UserID != "" && actor.KeyID == "" && actor.CollectorID == ""
}

func grantHasScope(grant domain.ResourceGrant, scope string) bool {
	for _, got := range grant.Scopes {
		if got == "*" || got == scope || got == ScopeAdmin {
			return true
		}
	}
	return false
}

func evidenceReferencesArtifact(item domain.EvidenceItem, artifactID string) bool {
	for _, ref := range item.SubjectRefs {
		if ref.Type == "artifact" && ref.ID == artifactID {
			return true
		}
	}
	return false
}

func scopesForRole(role string) []string {
	return identityapp.RoleScopes(role)
}

func oidcGroupsFromVerifiedToken(provider domain.SSOProvider, token string) []string {
	claimName := strings.TrimSpace(provider.GroupsClaim)
	if claimName == "" || token == "" || provider.Type != "oidc" {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil
	}
	return sortedStrings(stringClaimValues(claims[claimName]))
}

func stringClaimValues(value any) []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(raw string) {
		item := strings.TrimSpace(raw)
		if item == "" {
			return
		}
		if _, ok := seen[item]; ok {
			return
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	switch got := value.(type) {
	case string:
		add(got)
	case []any:
		for _, item := range got {
			if text, ok := item.(string); ok {
				add(text)
			}
		}
	}
	return out
}

func validSSOType(value string) bool {
	return value == "oidc" || value == "saml"
}

func normalizeJWKS(jwks map[string]any) (map[string]any, error) {
	value, err := (identityapp.PublicTrustMaterialValidator{}).NormalizeJWKS(jwks)
	return value, fromIdentityContextError(err)
}

func normalizeSAMLSigningCertificates(certs []string) ([]string, error) {
	value, err := (identityapp.PublicTrustMaterialValidator{}).NormalizeSAMLSigningCertificates(certs)
	return value, fromIdentityContextError(err)
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range in {
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func ternary(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}
