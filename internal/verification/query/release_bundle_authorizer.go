package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewReleaseBundleVerificationAuthorizer() application.Authorizer {
	return releaseBundleVerificationAuthorizer{}
}

type releaseBundleVerificationAuthorizer struct{}

func (releaseBundleVerificationAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if ctx == nil {
		return application.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.UserID == "" && actor.KeyID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if request.Scope != "verify:read" || request.TenantWide || !actor.HasScope(request.Scope) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	refs := request.Resources
	if request.ScopeOnly {
		if refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return nil
	}
	if refs.ProductID == "" || refs.ReleaseID == "" || refs != (application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID}) {
		return application.ErrForbidden
	}
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	if verificationResourceGrantAllows(actor, request.Scope, refs) {
		return nil
	}
	return application.ErrForbidden
}
