package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewSourceWriteAuthorizer() application.Authorizer { return sourceWriteAuthorizer{} }

type sourceWriteAuthorizer struct{}

func (sourceWriteAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.TenantID == "" || a.KeyID == "" && a.UserID == "" && a.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if r.Scope != "source:write" || !a.HasScope(r.Scope) && !a.HasScope("admin") {
		return application.ErrForbidden
	}
	if r.ScopeOnly {
		if r.TenantWide || r.Resources != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return nil
	}
	refs := r.Resources
	if r.TenantWide {
		if refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
	} else if refs.ProductID == "" || refs.ProjectID == "" || refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID}) {
		return application.ErrForbidden
	}
	if a.UserID == "" || a.KeyID != "" || a.CollectorID != "" {
		return nil
	}
	for _, g := range a.ResourceGrants {
		allowed := false
		for _, scope := range g.Scopes {
			if scope == r.Scope || scope == "admin" || scope == "*" {
				allowed = true
			}
		}
		if !allowed {
			continue
		}
		if (g.ResourceType == "" || g.ResourceType == "tenant") && (g.ResourceID == "" || g.ResourceID == a.TenantID) {
			return nil
		}
		if !r.TenantWide && (g.ResourceType == "product" && g.ResourceID == refs.ProductID || g.ResourceType == "project" && g.ResourceID == refs.ProjectID) {
			return nil
		}
	}
	return application.ErrForbidden
}
