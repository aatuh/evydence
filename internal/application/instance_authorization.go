package application

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// AuthorizeInstanceScope requires the exact issued scope. Tenant-level admin
// and wildcard scopes must not imply authority over other tenants.
func AuthorizeInstanceScope(ctx context.Context, actor identitydomain.Actor, scope string) error {
	if ctx == nil {
		return ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return ErrUnauthorized
	}
	if scope == "" || !actor.HasExplicitScope(scope) {
		return ErrForbidden
	}
	return nil
}
