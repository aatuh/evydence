package app

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

// Return the association that justified visibility so the focused query can
// recheck its grants. Artifact evidence grants use explicit, not derived, IDs.
func memorySBOMComponentVisibility(ctx context.Context, s *MemoryUnitOfWorkSnapshot, b domain.SBOM, product string, request evidencequery.SBOMComponentPageRequest) (application.ResourceReferences, bool, error) {
	root := application.ResourceReferences{ProductID: product, ReleaseID: b.ReleaseID}
	if request.TenantWide || b.ReleaseID != "" && slices.Contains(request.AllowedReleaseIDs, b.ReleaseID) || b.ArtifactID == "" && product != "" && slices.Contains(request.AllowedProductIDs, product) {
		return root, true, nil
	}
	if b.ArtifactID == "" {
		return application.ResourceReferences{}, false, nil
	}
	for id, e := range s.Evidence {
		if err := ctx.Err(); err != nil {
			return application.ResourceReferences{}, false, err
		}
		if e.ID != id || e.TenantID != b.TenantID || !memoryArtifactEvidenceParents(s, b.TenantID, e) || b.ReleaseID != "" && e.ReleaseID != "" && b.ReleaseID != e.ReleaseID {
			continue
		}
		granted := e.ProductID != "" && slices.Contains(request.AllowedProductIDs, e.ProductID) && (b.ReleaseID == "" || e.ProductID == product) || e.ProjectID != "" && slices.Contains(request.AllowedProjectIDs, e.ProjectID) || e.ReleaseID != "" && slices.Contains(request.AllowedReleaseIDs, e.ReleaseID)
		if !granted {
			continue
		}
		for _, ref := range e.SubjectRefs {
			if ref.Type == "artifact" && ref.ID == b.ArtifactID {
				return application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID}, true, nil
			}
		}
	}
	a := s.Artifacts[b.ArtifactID]
	for id, build := range s.BuildRuns {
		if err := ctx.Err(); err != nil {
			return application.ResourceReferences{}, false, err
		}
		if build.TenantID != b.TenantID {
			continue
		}
		refs, err := memoryOperationsCoordinates(s, b.TenantID, application.ResourceReferences{BuildID: id})
		if err != nil || b.ReleaseID != "" && b.ReleaseID != refs.ReleaseID {
			continue
		}
		granted := slices.Contains(request.AllowedProductIDs, refs.ProductID) && (b.ReleaseID == "" || refs.ProductID == product) || slices.Contains(request.AllowedProjectIDs, refs.ProjectID) || slices.Contains(request.AllowedReleaseIDs, refs.ReleaseID)
		if !granted {
			continue
		}
		for _, output := range build.Outputs {
			if output.ArtifactID == a.ID && output.Digest == a.Digest {
				return refs, true, nil
			}
		}
	}
	return application.ResourceReferences{}, false, nil
}
