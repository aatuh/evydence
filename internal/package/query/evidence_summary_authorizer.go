package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// The reader resolves and locks parent coordinates; this policy never loads
// aggregate state. Root grants authorize citation metadata within that scope.
func NewEvidenceSummaryAuthorizer() application.Authorizer { return evidenceSummaryAuthorizer{} }

type evidenceSummaryAuthorizer struct{}

func (evidenceSummaryAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if ctx == nil {
		return application.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.TenantID == "" || a.UserID == "" && a.KeyID == "" && a.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if r.Scope != "report:read" || !a.HasScope(r.Scope) && !a.HasScope("admin") {
		return application.ErrForbidden
	}
	refs := r.Resources
	if r.ScopeOnly {
		if r.TenantWide || refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return nil
	}
	if r.TenantWide != (refs == (application.ResourceReferences{})) || refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID, CustomerPackageID: refs.CustomerPackageID}) || refs != (application.ResourceReferences{}) && refs.ProductID == "" {
		return application.ErrForbidden
	}
	if a.UserID == "" || a.KeyID != "" || a.CollectorID != "" {
		return nil
	}
	for _, g := range a.ResourceGrants {
		allowed := false
		for _, scope := range g.Scopes {
			if scope == r.Scope || scope == "admin" || scope == "*" {
				allowed = true
			}
		}
		if !allowed {
			continue
		}
		if (g.ResourceType == "" || g.ResourceType == "tenant") && (g.ResourceID == "" || g.ResourceID == a.TenantID) || g.ResourceID != "" && (g.ResourceType == "product" && g.ResourceID == refs.ProductID || g.ResourceType == "project" && g.ResourceID == refs.ProjectID || g.ResourceType == "release" && g.ResourceID == refs.ReleaseID || g.ResourceType == "customer_security_package" && g.ResourceID == refs.CustomerPackageID) {
			return nil
		}
	}
	return application.ErrForbidden
}
