package authz

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// ArtifactVisibilityRequest carries only policy-derived grant coordinates and
// explicit subject filters. Implementations must verify tenant ownership and
// apply the filters before testing a bounded current association; no metadata
// or association inventory is returned.
type ArtifactVisibilityRequest struct {
	TenantID, ArtifactID, ProductID, ReleaseID              string
	AllowedProductIDs, AllowedProjectIDs, AllowedReleaseIDs []string
}

type ArtifactVisibilityReader interface {
	ArtifactVisible(context.Context, ArtifactVisibilityRequest) (bool, error)
}

type ArtifactVisibilityFunc func(context.Context, ArtifactVisibilityRequest) (bool, error)

func (f ArtifactVisibilityFunc) ArtifactVisible(ctx context.Context, request ArtifactVisibilityRequest) (bool, error) {
	if f == nil {
		return false, ErrForbidden
	}
	return f(ctx, request)
}

// AuthorizeWithArtifactVisibility is the explicit association-backed policy
// path for control links. Ordinary Authorize remains storage-free and denies
// scoped-human artifact requests when no association proof is available.
// The application supplies its transaction-owned, bounded visibility port.
func AuthorizeWithArtifactVisibility(ctx context.Context, actor identitydomain.Actor, request Request, reader ArtifactVisibilityReader) error {
	if request.Action != ActionControlEvidenceLink {
		return ErrForbidden
	}
	return authorizeWithArtifactVisibility(ctx, actor, request, reader)
}

func authorizeControlArtifact(ctx context.Context, actor identitydomain.Actor, scope string, request Request, reader ArtifactVisibilityReader) error {
	if err := authorizeResource(actor, scope, Request{Action: request.Action, Evaluation: ScopeEvaluation, Resources: ResourceReferences{TenantID: request.Resources.TenantID}}); err != nil {
		return err
	}
	refs := request.Resources
	refs.TenantID = "" // The preflight already verified an explicit tenant target.
	if !validResourceReferences(request.Action, refs) {
		return ErrForbidden
	}
	visibility := visibilityForGrants(actor, scope, true, true)
	if visibility.TenantWide {
		return nil
	}
	if reader == nil || len(visibility.ProductIDs)+len(visibility.ProjectIDs)+len(visibility.ReleaseIDs) == 0 {
		return ErrForbidden
	}
	visible, err := reader.ArtifactVisible(ctx, ArtifactVisibilityRequest{
		TenantID: visibility.TenantID, ArtifactID: refs.ArtifactID, ProductID: refs.ProductID, ReleaseID: refs.ReleaseID,
		AllowedProductIDs: visibility.ProductIDs, AllowedProjectIDs: visibility.ProjectIDs, AllowedReleaseIDs: visibility.ReleaseIDs,
	})
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !visible {
		return ErrForbidden
	}
	return nil
}
