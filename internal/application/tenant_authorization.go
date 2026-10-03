package application

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// AuthorizeTenantWideScope preserves the Ledger's tenant-wide authorization
// rule for focused queries. Human sessions need both an effective scope and a
// current tenant-level grant; API keys and collectors are scoped by the issued
// credential itself.
func AuthorizeTenantWideScope(ctx context.Context, actor identitydomain.Actor, scope string) error {
	if ctx == nil {
		return ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return ErrUnauthorized
	}
	if scope == "" || !actor.HasScope(scope) && !actor.HasScope("admin") {
		return ErrForbidden
	}
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	for _, grant := range actor.ResourceGrants {
		if grant.ResourceType != "" && grant.ResourceType != "tenant" || grant.ResourceID != "" && grant.ResourceID != actor.TenantID {
			continue
		}
		for _, grantedScope := range grant.Scopes {
			if grantedScope == scope || grantedScope == "admin" || grantedScope == "*" {
				return nil
			}
		}
	}
	return ErrForbidden
}
