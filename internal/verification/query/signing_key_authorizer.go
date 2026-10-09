package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewSigningKeyAdminAuthorizer() application.Authorizer { return signingKeyAdminAuthorizer{} }

type signingKeyAdminAuthorizer struct{}

func (signingKeyAdminAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if request.Scope != "keys:admin" || !request.TenantWide || request.ScopeOnly || request.Resources != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return application.AuthorizeTenantWideScope(ctx, actor, request.Scope)
}
