package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Incident authorization consumes only ownership already resolved by the
// transaction reader. It cannot infer grants from caller-supplied IDs.
func NewIncidentWriteAuthorizer() application.Authorizer { return incidentWriteAuthorizer{} }

type incidentWriteAuthorizer struct{}

func (incidentWriteAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := incidentContextError(ctx); err != nil {
		return err
	}
	_, id := incidentActor(a)
	if strings.TrimSpace(a.TenantID) == "" || strings.TrimSpace(id) == "" {
		return application.ErrUnauthorized
	}
	if r.Action != authz.ActionIncidentsManage || r.Scope != "" || r.ScopeOnly && r.TenantWide {
		return application.ErrForbidden
	}
	evaluation := authz.ResolvedEvaluation
	if r.ScopeOnly {
		evaluation = authz.ScopeEvaluation
	} else if r.TenantWide {
		evaluation = authz.TenantEvaluation
	}
	return authz.Authorize(ctx, a, authz.Request{Action: r.Action, Resources: r.Resources, Evaluation: evaluation})
}
