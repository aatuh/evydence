package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Native privileged commands bind one action. Capability and current tenant
// grants are evaluated centrally, never inferred from a request's scope string.
type tenantAdministrationAuthorizer struct{ action authz.Action }

func (p tenantAdministrationAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if request.Action != p.action || request.Scope != "" || !request.TenantWide || request.ScopeOnly || request.Resources != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return authz.Authorize(ctx, actor, authz.Request{Action: p.action})
}
