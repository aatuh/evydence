package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewEvidenceBundleAuthorizer consumes validated, resolved coordinates only.
// Storage owns coordinate validation; this policy never dereferences IDs.
func NewEvidenceBundleAuthorizer() application.Authorizer { return evidenceBundleAuthorizer{} }

type evidenceBundleAuthorizer struct{}

func (evidenceBundleAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if ctx == nil {
		return application.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.UserID == "" && actor.KeyID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if request.Scope != "bundle:read" || request.TenantWide || !actor.HasScope(request.Scope) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	refs := request.Resources
	if request.ScopeOnly {
		if refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return nil
	}
	if refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID}) || (refs.ProjectID != "" || refs.ReleaseID != "" || refs.BuildID != "" || refs.DeploymentID != "") && refs.ProductID == "" {
		return application.ErrForbidden
	}
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	for _, grant := range actor.ResourceGrants {
		allowed := false
		for _, scope := range grant.Scopes {
			if scope == request.Scope || scope == "admin" || scope == "*" {
				allowed = true
			}
		}
		if !allowed {
			continue
		}
		if (grant.ResourceType == "" || grant.ResourceType == "tenant") && (grant.ResourceID == "" || grant.ResourceID == actor.TenantID) || grant.ResourceID != "" && (grant.ResourceType == "product" && grant.ResourceID == refs.ProductID || grant.ResourceType == "project" && grant.ResourceID == refs.ProjectID || grant.ResourceType == "release" && grant.ResourceID == refs.ReleaseID) {
			return nil
		}
	}
	return application.ErrForbidden
}
