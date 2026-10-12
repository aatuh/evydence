package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewSourceWriteAuthorizer accepts only registered Integration source commands.
// Current tenant-owned parent coordinates are resolved by the command guards.
func NewSourceWriteAuthorizer() application.Authorizer { return sourceWriteAuthorizer{} }

type sourceWriteAuthorizer struct{}

func (sourceWriteAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if request.Scope != "" || !isSourceWriteAction(request.Action) || request.ScopeOnly && request.TenantWide {
		return application.ErrForbidden
	}
	evaluation := authz.ResolvedEvaluation
	if request.ScopeOnly {
		evaluation = authz.ScopeEvaluation
	} else if request.TenantWide {
		evaluation = authz.TenantEvaluation
	}
	return authz.Authorize(ctx, actor, authz.Request{Action: request.Action, Resources: request.Resources, Evaluation: evaluation})
}

func isSourceWriteAction(action authz.Action) bool {
	switch action {
	case authz.ActionSourceRepositoriesCreate, authz.ActionSourceCommitsRecord, authz.ActionSourceBranchesUpsert,
		authz.ActionPullRequestsRecord, authz.ActionSourceSnapshotsRecord:
		return true
	default:
		return false
	}
}
