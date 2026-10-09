package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Artifacts have tenant ownership, not a product/release grant coordinate.
// Humans therefore need an explicit tenant grant; keys/collectors need scope.
func NewCosignVerificationAuthorizer() application.Authorizer { return cosignVerificationAuthorizer{} }

type cosignVerificationAuthorizer struct{}

func (cosignVerificationAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, r application.AuthorizationRequest) error {
	if ctx == nil || actor.TenantID == "" || actor.UserID == "" && actor.KeyID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.Scope != "verify:read" || !actor.HasScope(r.Scope) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	if r.ScopeOnly {
		if r.Resources != (application.ResourceReferences{}) || r.TenantWide {
			return application.ErrForbidden
		}
		return nil
	}
	if r.TenantWide || r.Resources.ArtifactID == "" || r.Resources != (application.ResourceReferences{ArtifactID: r.Resources.ArtifactID}) {
		return application.ErrForbidden
	}
	if actor.UserID != "" && actor.KeyID == "" && actor.CollectorID == "" && !verificationResourceGrantAllows(actor, r.Scope, application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return nil
}
