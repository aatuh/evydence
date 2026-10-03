package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewRetentionAuthorizer() application.Authorizer { return retentionAuthorizer{} }

type retentionAuthorizer struct{}

func (retentionAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if (request.Scope != "admin" && request.Scope != "verify:read") || !request.TenantWide || request.ScopeOnly || request.Resources != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return application.AuthorizeTenantWideScope(ctx, actor, request.Scope)
}
