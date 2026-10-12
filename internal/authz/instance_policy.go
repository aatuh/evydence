package authz

import (
	"context"
	"strings"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func explicitInstanceAuthority(actor identitydomain.Actor) bool {
	return actor.HasExplicitScope("instance:admin")
}

// CheckAPIKeyScopeDelegation is an additional issuance constraint, not
// authorization to create a key. Callers must also authorize APIKeysManage.
// Preserve inert unknown/blank/duplicate scopes and never normalize actor
// claims into explicit instance authority or mutate requested scope values.
func CheckAPIKeyScopeDelegation(actor identitydomain.Actor, scopes []string) error {
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "instance:admin" && !explicitInstanceAuthority(actor) {
			return ErrForbidden
		}
	}
	return nil
}

// AuthorizeMetrics chooses and authorizes the existing tenant/instance view.
// Explicit instance capability never comes from a tenant grant or wildcard.
func AuthorizeMetrics(ctx context.Context, actor identitydomain.Actor) (Action, error) {
	action := ActionTenantMetricsRead
	if explicitInstanceAuthority(actor) {
		action = ActionInstanceMetricsRead
	}
	if err := Authorize(ctx, actor, Request{Action: action}); err != nil {
		return "", err
	}
	return action, nil
}
