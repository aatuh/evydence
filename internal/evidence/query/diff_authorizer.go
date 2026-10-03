package query

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// NewDiffAuthorizer reuses evidence-read grants for verified diff coordinates
// and delegates artifact associations to the release-owned read policy.
func NewDiffAuthorizer(artifacts application.Authorizer) (application.Authorizer, error) {
	if artifacts == nil {
		return nil, ErrValidation
	}
	return diffAuthorizer{artifacts}, nil
}

type diffAuthorizer struct{ artifacts application.Authorizer }

func (a diffAuthorizer) Authorize(ctx context.Context, actor identitydomain.Actor, r application.AuthorizationRequest) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.Scope != scopeEvidenceRead || r.TenantWide {
		return application.ErrForbidden
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{}, true); err != nil {
		return err
	}
	refs := r.Resources
	if r.ScopeOnly {
		if refs != (application.ResourceReferences{}) {
			return application.ErrForbidden
		}
		return nil
	}
	if refs.ArtifactID != "" {
		if refs != (application.ResourceReferences{ArtifactID: refs.ArtifactID}) {
			return application.ErrForbidden
		}
		return a.artifacts.Authorize(ctx, actor, r)
	}
	if refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID}) {
		return application.ErrForbidden
	}
	return authorizeEvidenceRead(actor, EvidencePoint{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID}, false)
}
