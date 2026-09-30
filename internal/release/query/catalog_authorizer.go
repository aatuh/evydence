package query

import (
	"context"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewCatalogAuthorizer returns the actor-grant policy for release-catalog
// queries. The owning query service supplies only tenant-verified product,
// project, and release coordinates from its database reader.
func NewCatalogAuthorizer() application.Authorizer {
	return catalogAuthorizer{}
}

type catalogAuthorizer struct{}

func (catalogAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if !catalogScope(request.Scope) || !actor.HasScope(request.Scope) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	if request.Scope == "product:write" {
		if !request.TenantWide || request.ScopeOnly || request.Resources != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return authorizeCatalogGrant(actor, request.Scope, application.ResourceReferences{}, true)
	}
	if request.TenantWide {
		return authorizeCatalogGrant(actor, request.Scope, application.ResourceReferences{}, true)
	}
	if request.ScopeOnly {
		return nil
	}
	if !validCatalogReferences(request.Scope, request.Resources) {
		return application.ErrForbidden
	}
	return authorizeCatalogGrant(actor, request.Scope, request.Resources, false)
}

func catalogScope(scope string) bool {
	return scope == ScopeProductRead || scope == "product:write" || scope == scopeProjectRead || scope == "project:write" || scope == scopeReleaseRead || scope == scopeBuildRead
}

func validCatalogReferences(scope string, refs application.ResourceReferences) bool {
	switch scope {
	case ScopeProductRead:
		return refs.ProductID != "" && refs == (application.ResourceReferences{ProductID: refs.ProductID})
	case "project:write":
		return refs.ProductID != "" && refs == (application.ResourceReferences{ProductID: refs.ProductID})
	case scopeProjectRead:
		return refs.ProductID != "" && refs.ProjectID != "" && refs == (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID})
	case scopeReleaseRead:
		return refs.ProductID != "" && refs.ReleaseID != "" && refs == (application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case scopeBuildRead:
		return refs.ProductID != "" && refs.ProjectID != "" && refs.ReleaseID != "" && refs.BuildID != "" && refs == (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID})
	default:
		return false
	}
}

func authorizeCatalogGrant(actor identitydomain.Actor, scope string, refs application.ResourceReferences, tenantWide bool) error {
	// API keys and collectors are constrained by their scopes; human sessions
	// additionally require a current resource grant.
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	for _, grant := range actor.ResourceGrants {
		if !catalogGrantHasScope(grant, scope) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return nil
			}
		case "product":
			if !tenantWide && refs.ProductID != "" && grant.ResourceID == refs.ProductID {
				return nil
			}
		case "project":
			if !tenantWide && refs.ProjectID != "" && grant.ResourceID == refs.ProjectID {
				return nil
			}
		case "release":
			if !tenantWide && refs.ReleaseID != "" && grant.ResourceID == refs.ReleaseID {
				return nil
			}
		}
	}
	return application.ErrForbidden
}

func catalogGrantHasScope(grant identitydomain.ResourceGrant, scope string) bool {
	for _, got := range grant.Scopes {
		if got == scope || got == "admin" || got == "*" {
			return true
		}
	}
	return false
}
