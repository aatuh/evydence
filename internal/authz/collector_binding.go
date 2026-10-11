package authz

import (
	"strings"
	"unicode/utf8"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// CollectorCredentialBinding is current storage-owned identity/capability
// metadata, not a caller's asserted collector ID or a product grant.
type CollectorCredentialBinding struct {
	ID, TenantID, APIKeyID, Status string
	AllowedScopes                  []string
}

// CheckCollectorCredentialBinding constrains an already-verified API key.
// Each issued capability must be explicitly declared; wildcard, admin,
// padding, or a grant never expands a narrower collector binding. Unknown
// capabilities remain inert in the closed action registry. Duplicate scopes
// and a key narrower than its declared binding remain compatible.
func CheckCollectorCredentialBinding(actor identitydomain.Actor, binding CollectorCredentialBinding) error {
	for _, id := range []string{binding.ID, binding.TenantID, binding.APIKeyID} {
		if id == "" || len(id) > 1024 || strings.TrimSpace(id) != id || !utf8.ValidString(id) || strings.ContainsRune(id, 0) {
			return ErrForbidden
		}
	}
	if actor.TenantID != binding.TenantID || actor.KeyID != binding.APIKeyID || actor.UserID != "" || actor.SessionID != "" || actor.CollectorID != "" && actor.CollectorID != binding.ID || binding.Status != "active" || len(binding.AllowedScopes) == 0 || len(binding.AllowedScopes) > 1024 || len(actor.Scopes) == 0 || len(actor.Scopes) > 1024 {
		return ErrForbidden
	}
	allowed := make(map[string]struct{}, len(binding.AllowedScopes))
	for _, scope := range binding.AllowedScopes {
		if scope == "" || len(scope) > 128 || strings.TrimSpace(scope) != scope || !utf8.ValidString(scope) || strings.ContainsRune(scope, 0) {
			return ErrForbidden
		}
		allowed[scope] = struct{}{}
	}
	for _, scope := range actor.Scopes {
		if _, ok := allowed[scope]; !ok {
			return ErrForbidden
		}
	}
	return nil
}
