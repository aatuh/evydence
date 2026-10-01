package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func NewEvidenceVerificationAuthorizer() application.Authorizer {
	return evidenceVerificationAuthorizer{}
}

type evidenceVerificationAuthorizer struct{}

func (evidenceVerificationAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if ctx == nil || actor.TenantID == "" || actor.UserID == "" && actor.KeyID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if request.Scope != "verify:read" || !actor.HasScope(request.Scope) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	refs := request.Resources
	if request.ScopeOnly {
		if refs != (application.ResourceReferences{}) || request.TenantWide {
			return application.ErrForbidden
		}
		return nil
	}
	if refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID}) || request.TenantWide != (refs == application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	if verificationResourceGrantAllows(actor, request.Scope, refs) {
		return nil
	}
	return application.ErrForbidden
}

func verificationResourceGrantAllows(actor identitydomain.Actor, scope string, refs application.ResourceReferences) bool {
	for _, grant := range actor.ResourceGrants {
		allowed := false
		for _, candidate := range grant.Scopes {
			if candidate == scope || candidate == "admin" || candidate == "*" {
				allowed = true
			}
		}
		if !allowed {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true
			}
		case "product":
			if refs.ProductID != "" && grant.ResourceID == refs.ProductID {
				return true
			}
		case "project":
			if refs.ProjectID != "" && grant.ResourceID == refs.ProjectID {
				return true
			}
		case "release":
			if refs.ReleaseID != "" && grant.ResourceID == refs.ReleaseID {
				return true
			}
		}
	}
	return false
}
