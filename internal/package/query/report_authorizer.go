package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewReportAuthorizer authorizes report generation for an explicit product
// and optional release. Durable repositories must also verify their ownership.
func NewReportAuthorizer() application.Authorizer { return reportAuthorizer{} }

type reportAuthorizer struct{}

func (reportAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if ctx == nil {
		return application.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.UserID == "" && actor.KeyID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	refs := request.Resources
	if request.Scope != "report:read" || request.ScopeOnly || request.TenantWide || refs.ProductID == "" || refs != (application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID}) || !actor.HasScope(request.Scope) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	if !releaseReportAllowed(actor, refs.ProductID, refs.ReleaseID) {
		return application.ErrForbidden
	}
	return nil
}
