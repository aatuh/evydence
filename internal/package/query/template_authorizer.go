package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewTemplateAuthorizer preserves the tenant-wide report permission required
// for template definitions and metadata-only materialized reports.
func NewTemplateAuthorizer() application.Authorizer {
	return tenantWideCommandAuthorizer{scope: "report:read"}
}

// NewBundleImportAuthorizer requires tenant-wide permission to record an
// imported manifest receipt; source labels do not grant target-tenant access.
func NewBundleImportAuthorizer() application.Authorizer {
	return tenantWideCommandAuthorizer{scope: "bundle:write"}
}

type tenantWideCommandAuthorizer struct{ scope string }

func (a tenantWideCommandAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if a.scope == "" || request.Scope != a.scope || request.Resources != (application.ResourceReferences{}) || request.ScopeOnly == request.TenantWide {
		return application.ErrForbidden
	}
	return application.AuthorizeTenantWideScope(ctx, actor, request.Scope)
}
