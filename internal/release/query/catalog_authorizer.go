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
	if request.Scope != "" || !isCatalogAction(request.Action) {
		return application.ErrForbidden
	}
	if request.Action == authz.ActionProductsCreate && (!request.TenantWide || request.ScopeOnly) {
		return application.ErrForbidden
	}
	evaluation := authz.ResolvedEvaluation
	if request.TenantWide {
		evaluation = authz.TenantEvaluation
	} else if request.ScopeOnly {
		evaluation = authz.ScopeEvaluation
	}
	return authz.Authorize(ctx, actor, authz.Request{Action: request.Action, Resources: request.Resources, Evaluation: evaluation})
}

// An authorizer for one context cannot select a foreign context's operation.
func isCatalogAction(action authz.Action) bool {
	switch action {
	case authz.ActionProductsRead, authz.ActionProductsCreate,
		authz.ActionProjectsRead, authz.ActionProjectsCreate,
		authz.ActionReleasesRead, authz.ActionReleasesManage,
		authz.ActionBuildsRead, authz.ActionBuildsCreate,
		authz.ActionBuildAttestationsCreate, authz.ActionReleaseCandidatesCreate:
		return true
	default:
		return false
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
