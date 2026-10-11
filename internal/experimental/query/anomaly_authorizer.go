package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewAnomalyAuthorizer() application.Authorizer { return anomalyAuthorizer{} }

type anomalyAuthorizer struct{}

func (anomalyAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Action != authz.ActionAnomalyReportsGenerate || r.Scope != "" || r.Resources.TenantID != "" {
		return application.ErrForbidden
	}
	evaluation := authz.ResolvedEvaluation
	if r.ScopeOnly {
		if r.TenantWide || r.Resources != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		evaluation = authz.ScopeEvaluation
	} else if r.TenantWide {
		if r.Resources != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		evaluation = authz.TenantEvaluation
	}
	return authz.Authorize(ctx, a, authz.Request{Action: r.Action, Resources: r.Resources, Evaluation: evaluation})
}
