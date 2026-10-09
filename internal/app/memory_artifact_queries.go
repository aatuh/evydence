package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releasequery.ArtifactPointReader = memoryReleaseCatalogRepository{}

// Focused test-backend point/grant readers share the SQL association rules.
// Their memory scans and snapshot transactions are not SQL work/transfer or
// lock/durability evidence. Guard projections omit descriptive metadata.
func (r memoryReleaseCatalogRepository) GetArtifactPoint(ctx context.Context, req releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	return r.readArtifactPoint(ctx, req, true)
}
func (r memoryReleaseCatalogRepository) ReadBuildArtifactGrant(ctx context.Context, req releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	return r.readArtifactPoint(ctx, req, false)
}
func (r memoryReleaseCatalogRepository) readArtifactPoint(ctx context.Context, req releasequery.ArtifactReadRequest, metadata bool) (releasequery.ArtifactPoint, error) {
	if req.TenantWide == (len(req.AllowedProductIDs)+len(req.AllowedProjectIDs)+len(req.AllowedReleaseIDs) != 0) {
		return releasequery.ArtifactPoint{}, releasequery.ErrValidation
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		return releasequery.ArtifactPoint{}, releasequery.ErrNotFound
	}
	grants, err := memoryArtifactReadGrants(req)
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	var out releasequery.ArtifactPoint
	err = r.catalogQueryRead(ctx, req.TenantID, req.ID, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryArtifactPointInSnapshot(s, req, grants, metadata)
		return err
	})
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	return out, nil
}

type memoryArtifactGrantSets struct{ products, projects, releases map[string]bool }

func memoryArtifactReadGrants(req releasequery.ArtifactReadRequest) (memoryArtifactGrantSets, error) {
	if req.TenantWide == (len(req.AllowedProductIDs)+len(req.AllowedProjectIDs)+len(req.AllowedReleaseIDs) != 0) {
		return memoryArtifactGrantSets{}, releasequery.ErrValidation
	}
	products, projects, releases := make(map[string]bool), make(map[string]bool), make(map[string]bool)
	for _, group := range []struct {
		ids     []string
		allowed map[string]bool
	}{{req.AllowedProductIDs, products}, {req.AllowedProjectIDs, projects}, {req.AllowedReleaseIDs, releases}} {
		for _, id := range group.ids {
			if !memoryMembershipQueryText(id, 1024) {
				return memoryArtifactGrantSets{}, releasequery.ErrValidation
			}
			group.allowed[id] = true
		}
	}
	return memoryArtifactGrantSets{products, projects, releases}, nil
}

func memoryArtifactPointInSnapshot(s *MemoryUnitOfWorkSnapshot, req releasequery.ArtifactReadRequest, grants memoryArtifactGrantSets, metadata bool) (releasequery.ArtifactPoint, error) {
	a, ok := s.Artifacts[req.ID]
	if !ok || a.ID != req.ID || a.TenantID != req.TenantID {
		return releasequery.ArtifactPoint{}, releasequery.ErrNotFound
	}
	visible := req.TenantWide || memoryArtifactVisible(s, a, grants.products, grants.projects, grants.releases)
	out := releasequery.ArtifactPoint{Artifact: releasedomain.Artifact{ID: a.ID, TenantID: a.TenantID, CreatedAt: a.CreatedAt}, Visible: visible}
	if metadata {
		if !memoryMembershipText(a.Name, 65536) || !memoryMembershipText(a.MediaType, 65536) || !memoryMembershipText(a.Digest, 71) || a.Size < 0 {
			return releasequery.ArtifactPoint{}, releasequery.ErrInvalidProjection
		}
		out.Artifact = artifactToReleaseContext(a)
	}
	return out, nil
}

// Nested read-only authorization stays in the already-locked snapshot rather
// than opening or re-entering its UnitOfWork. Private metadata is never selected.
type memorySnapshotArtifactReader struct{ state *MemoryUnitOfWorkSnapshot }

func (r memorySnapshotArtifactReader) GetArtifactPoint(ctx context.Context, req releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	if ctx == nil || r.state == nil {
		return releasequery.ArtifactPoint{}, releasequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	grants, err := memoryArtifactReadGrants(req)
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	req.ID = strings.TrimSpace(req.ID)
	if !memoryMembershipQueryText(req.ID, 1024) || !memoryMembershipQueryText(req.TenantID, 1024) {
		return releasequery.ArtifactPoint{}, releasequery.ErrValidation
	}
	return memoryArtifactPointInSnapshot(r.state, req, grants, false)
}

func memoryArtifactVisible(s *MemoryUnitOfWorkSnapshot, a domain.Artifact, products, projects, releases map[string]bool) bool {
	_, visible := memoryArtifactAssociation(s, a, products, projects, releases)
	return visible
}

func memoryArtifactAssociation(s *MemoryUnitOfWorkSnapshot, a domain.Artifact, products, projects, releases map[string]bool) (application.ResourceReferences, bool) {
	for _, e := range s.Evidence {
		if e.TenantID != a.TenantID || !products[e.ProductID] && !projects[e.ProjectID] && !releases[e.ReleaseID] {
			continue
		}
		if !memoryArtifactEvidenceParents(s, a.TenantID, e) {
			continue
		}
		for _, ref := range e.SubjectRefs {
			if ref.Type == "artifact" && ref.ID == a.ID {
				return application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID}, true
			}
		}
	}
	for id, b := range s.BuildRuns {
		if b.TenantID != a.TenantID {
			continue
		}
		refs, err := memoryOperationsCoordinates(s, a.TenantID, application.ResourceReferences{BuildID: id})
		if err != nil || !products[refs.ProductID] && !projects[refs.ProjectID] && !releases[refs.ReleaseID] {
			continue
		}
		for _, output := range b.Outputs {
			if output.ArtifactID == a.ID && output.Digest == a.Digest {
				return application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID}, true
			}
		}
	}
	return application.ResourceReferences{}, false
}

// Evidence associations grant through their explicit references, not derived
// parents. Every supplied parent must be owned and the supplied pairs agree.
func memoryArtifactEvidenceParents(s *MemoryUnitOfWorkSnapshot, tenant string, e domain.EvidenceItem) bool {
	if e.ProductID != "" {
		p, ok := s.Products[e.ProductID]
		if !ok || p.ID != e.ProductID || p.TenantID != tenant {
			return false
		}
	}
	j, project := s.Projects[e.ProjectID]
	if e.ProjectID != "" && (!project || j.ID != e.ProjectID || j.TenantID != tenant) {
		return false
	}
	r, release := s.Releases[e.ReleaseID]
	if e.ReleaseID != "" && (!release || r.ID != e.ReleaseID || r.TenantID != tenant) {
		return false
	}
	if e.ProductID != "" && e.ProjectID != "" && e.ProductID != j.ProductID || e.ProductID != "" && e.ReleaseID != "" && e.ProductID != r.ProductID || e.ProjectID != "" && e.ReleaseID != "" && j.ProductID != r.ProductID {
		return false
	}
	return true
}

func (r memoryReleaseCatalogRepository) ReadBuildArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if !memoryMembershipQueryText(id, 1024) {
		return releasedomain.Artifact{}, ErrValidation
	}
	var out releasedomain.Artifact
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		a, ok := s.Artifacts[id]
		if !ok || a.ID != id || a.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryMembershipText(a.Digest, 71) {
			return ErrConflict
		}
		out = releasedomain.Artifact{ID: a.ID, TenantID: a.TenantID, Digest: a.Digest}
		return nil
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return out, nil
}
