package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewPackageAccessAuthorizer() application.Authorizer { return packageAccessAuthorizer{} }

type packageAccessAuthorizer struct{}

func (packageAccessAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if ctx == nil {
		return application.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.UserID == "" && actor.KeyID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if request.Scope != "package:read" || request.TenantWide || !actor.HasScope(request.Scope) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	refs := request.Resources
	if request.ScopeOnly {
		if refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return nil
	}
	if refs.ProductID == "" || refs.CustomerPackageID == "" || refs != (application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID, CustomerPackageID: refs.CustomerPackageID}) {
		return application.ErrForbidden
	}
	if releaseScopeAllowed(actor, request.Scope, refs.ProductID, refs.ReleaseID) {
		return nil
	}
	for _, grant := range actor.ResourceGrants {
		if grant.ResourceType != "customer_security_package" || grant.ResourceID != refs.CustomerPackageID {
			continue
		}
		for _, scope := range grant.Scopes {
			if scope == request.Scope || scope == "admin" || scope == "*" {
				return nil
			}
		}
	}
	return application.ErrForbidden
}
