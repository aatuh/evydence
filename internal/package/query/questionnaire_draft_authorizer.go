package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewQuestionnaireDraftAuthorizer() application.Authorizer { return questionnaireDraftAuthorizer{} }

type questionnaireDraftAuthorizer struct{}

func (questionnaireDraftAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if ctx == nil {
		return application.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.TenantID == "" || a.UserID == "" && a.KeyID == "" && a.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if r.Scope != "package:read" || !a.HasScope(r.Scope) && !a.HasScope("admin") {
		return application.ErrForbidden
	}
	refs := r.Resources
	if r.ScopeOnly {
		if r.TenantWide || refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return nil
	}
	if refs != (application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID}) || r.TenantWide != (refs == (application.ResourceReferences{})) || refs.ReleaseID != "" && refs.ProductID == "" {
		return application.ErrForbidden
	}
	if !releaseScopeAllowed(a, r.Scope, refs.ProductID, refs.ReleaseID) {
		return application.ErrForbidden
	}
	return nil
}
