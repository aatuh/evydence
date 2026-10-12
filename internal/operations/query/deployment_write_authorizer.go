package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewDeploymentWriteAuthorizer() application.Authorizer { return deploymentWriteAuthorizer{} }

type deploymentWriteAuthorizer struct{}

func (deploymentWriteAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.TenantID == "" || a.KeyID == "" && a.UserID == "" && a.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if r.Scope != "" || r.TenantWide || r.Action != authz.ActionEnvironmentsCreate && r.Action != authz.ActionDeploymentsRecord {
		return application.ErrForbidden
	}
	evaluation := authz.ResolvedEvaluation
	if r.ScopeOnly {
		evaluation = authz.ScopeEvaluation
	}
	return authz.Authorize(ctx, a, authz.Request{Action: r.Action, Resources: r.Resources, Evaluation: evaluation})
}
