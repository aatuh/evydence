package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
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
	if r.Scope != ScopeIncidentWrite || !a.HasScope(r.Scope) && !a.HasScope("admin") {
		return application.ErrForbidden
	}
	refs := r.Resources
	if r.ScopeOnly {
		if r.TenantWide || refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return nil
	}
	if r.TenantWide {
		if refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
	} else if refs.ProductID == "" || refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID}) {
		return application.ErrForbidden
	}
	if a.UserID == "" || a.KeyID != "" || a.CollectorID != "" {
		return nil
	}
	for _, grant := range a.ResourceGrants {
		allowed := false
		for _, scope := range grant.Scopes {
			if scope == r.Scope || scope == "admin" || scope == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == a.TenantID {
				return nil
			}
		case "product":
			if grant.ResourceID != "" && grant.ResourceID == refs.ProductID {
				return nil
			}
		case "project":
			if grant.ResourceID != "" && grant.ResourceID == refs.ProjectID {
				return nil
			}
		case "release":
			if grant.ResourceID != "" && grant.ResourceID == refs.ReleaseID {
				return nil
			}
		}
	}
	return application.ErrForbidden
}
