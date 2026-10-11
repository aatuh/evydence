package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// The native command port binds one action, not a caller-selected capability.
// Only envelope translation lives here; grant and resource policy is central.
type packageCommandAuthorizer struct{ action authz.Action }

func (p packageCommandAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if ctx == nil {
		switch p.action {
		case authz.ActionCRAReadinessHTMLGenerate, authz.ActionCustomerPackagesAccess, authz.ActionPortalAccessManage:
			return application.ErrForbidden
		default:
			return application.ErrUnauthorized
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if request.Action != p.action || request.Scope != "" || request.Resources.TenantID != "" {
		return application.ErrForbidden
	}
	evaluation := authz.ResolvedEvaluation
	if request.ScopeOnly {
		if request.TenantWide || request.Resources != (application.ResourceReferences{}) || p.action == authz.ActionCRAReadinessHTMLGenerate {
			return application.ErrForbidden
		}
		evaluation = authz.ScopeEvaluation
	} else if request.TenantWide {
		if request.Resources != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		evaluation = authz.TenantEvaluation
	}
	return authz.Authorize(ctx, actor, authz.Request{Action: p.action, Resources: request.Resources, Evaluation: evaluation})
}
