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
	TenantWide                                              bool
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
// path for registered artifact references. Ordinary Authorize remains storage-free and denies
// scoped-human artifact requests when no association proof is available.
// The application supplies its transaction-owned, bounded visibility port.
func AuthorizeWithArtifactVisibility(ctx context.Context, actor identitydomain.Actor, request Request, reader ArtifactVisibilityReader) error {
	if !allowsArtifactVisibility(request.Action) {
		return ErrForbidden
	}
	return authorizeWithArtifactVisibility(ctx, actor, request, reader)
}

func allowsArtifactVisibility(action Action) bool {
	switch action {
	case ActionControlEvidenceLink, ActionArtifactsRead, ActionArtifactsWrite, ActionEvidenceWrite, ActionSecurityEvidenceWrite,
		ActionEvidenceDiffsCreate, ActionVEXPreviewRead, ActionBuildsCreate,
		ActionBuildAttestationsCreate, ActionReleaseCandidatesCreate:
		return true
	default:
		return false
	}
}

func authorizeArtifact(ctx context.Context, actor identitydomain.Actor, scope string, request Request, reader ArtifactVisibilityReader) error {
	if err := authorizeResource(actor, scope, Request{Action: request.Action, Evaluation: ScopeEvaluation, Resources: ResourceReferences{TenantID: request.Resources.TenantID}}); err != nil {
		return err
	}
	refs := request.Resources
	refs.TenantID = "" // The preflight already verified an explicit tenant target.
	if request.Action == ActionControlEvidenceLink && !validResourceReferences(request.Action, refs) ||
		request.Action != ActionControlEvidenceLink && refs != (ResourceReferences{ArtifactID: refs.ArtifactID}) {
		return ErrForbidden
	}
	visibility := visibilityForGrants(actor, scope, true, true, false)
	// Issued credentials retain their capability check; commands independently
	// validate the tenant-owned artifact and digest. Control links and filtered
	// artifact point reads retain their tenant-grant behavior. Other human
	// references require a current artifact existence/visibility proof even
	// with a tenant-wide grant.
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" || (request.Action == ActionControlEvidenceLink || request.Action == ActionArtifactsRead) && visibility.TenantWide {
		return nil
	}
	if reader == nil || !visibility.TenantWide && len(visibility.ProductIDs)+len(visibility.ProjectIDs)+len(visibility.ReleaseIDs) == 0 {
		return ErrForbidden
	}
	visible, err := reader.ArtifactVisible(ctx, ArtifactVisibilityRequest{
		TenantID: visibility.TenantID, ArtifactID: refs.ArtifactID, ProductID: refs.ProductID, ReleaseID: refs.ReleaseID,
		TenantWide:        visibility.TenantWide,
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
