package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewTemplateAuthorizer preserves the tenant-wide report permission required
// for template definitions and metadata-only materialized reports.
func NewTemplateAuthorizer() application.Authorizer { return templateAuthorizer{} }

type templateAuthorizer struct{}

func (templateAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if request.Scope != "report:read" || request.Resources != (application.ResourceReferences{}) || request.ScopeOnly == request.TenantWide {
		return application.ErrForbidden
	}
	return application.AuthorizeTenantWideScope(ctx, actor, request.Scope)
}
