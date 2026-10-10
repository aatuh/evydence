package query

import (
	"context"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewCatalogAuthorizer binds context requests to the registered central policy.
// Ownership readers still supply only current, tenant-verified coordinates.
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
	action := catalogAction(request.Scope)
	if action == authz.ActionProductsCreate && (!request.TenantWide || request.ScopeOnly) {
		return application.ErrForbidden
	}
	evaluation := authz.ResolvedEvaluation
	if request.TenantWide {
		evaluation = authz.TenantEvaluation
	} else if request.ScopeOnly {
		evaluation = authz.ScopeEvaluation
	}
	return authz.Authorize(ctx, actor, authz.Request{Action: action, Resources: request.Resources, Evaluation: evaluation})
}

// This fixed binding preserves the existing context-port request contract
// during migration; arbitrary capabilities cannot select a catalog policy.
func catalogAction(scope string) authz.Action {
	switch scope {
	case ScopeProductRead:
		return authz.ActionProductsRead
	case "product:write":
		return authz.ActionProductsCreate
	case scopeProjectRead:
		return authz.ActionProjectsRead
	case "project:write":
		return authz.ActionProjectsCreate
	case scopeReleaseRead:
		return authz.ActionReleasesRead
	case "release:write":
		return authz.ActionReleasesManage
	case scopeBuildRead:
		return authz.ActionBuildsRead
	case "build:write":
		return authz.ActionBuildsCreate
	default:
		return ""
	}
}

// This capability predicate is also used by bounded artifact/candidate read
// filters; it does not authorize an operation or replace the central policy.
func catalogGrantHasScope(grant identitydomain.ResourceGrant, scope string) bool {
	for _, got := range grant.Scopes {
		if got == scope || got == "admin" || got == "*" {
			return true
		}
	}
	return false
}
