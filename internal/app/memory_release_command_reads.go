package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// Focused test-backend identity reads use the current coherent snapshot. They
// select only command coordinates and do not establish SQL locks or budgets.
func (r memoryReleaseCatalogRepository) ReadBuildProject(ctx context.Context, tenant, id string) (releasedomain.Project, error) {
	var out releasedomain.Project
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProjectID: id})
		if err != nil {
			return err
		}
		out = releasedomain.Project{ID: id, TenantID: tenant, ProductID: refs.ProductID}
		return nil
	})
	if err != nil {
		return releasedomain.Project{}, err
	}
	return out, nil
}
func (r memoryReleaseCatalogRepository) ReadBuildRelease(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	var out releasedomain.Release
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: id})
		if err != nil {
			return err
		}
		v := s.Releases[id]
		if !memoryMembershipText(v.Version, 65536) {
			return ErrConflict
		}
		out = releasedomain.Release{ID: id, TenantID: tenant, ProductID: refs.ProductID, Version: v.Version}
		return nil
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return out, nil
}
func (r memoryReleaseCatalogRepository) ReadBuildCreationScope(ctx context.Context, tenant, project, release string) (releaseapp.BuildCreationCoordinates, error) {
	if !memoryMembershipQueryText(release, 1024) {
		return releaseapp.BuildCreationCoordinates{}, ErrValidation
	}
	var out releaseapp.BuildCreationCoordinates
	err := memoryGovernanceRead(ctx, r.uow, tenant, project, func(s *MemoryUnitOfWorkSnapshot) error {
		p, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProjectID: project})
		if err != nil {
			return err
		}
		r, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: release})
		if err != nil {
			return err
		}
		out = releaseapp.BuildCreationCoordinates{TenantID: tenant, ProjectID: project, ProductID: p.ProductID, ReleaseID: release, ReleaseProductID: r.ProductID}
		return nil
	})
	if err != nil {
		return releaseapp.BuildCreationCoordinates{}, err
	}
	return out, nil
}
func (r memoryReleaseCatalogRepository) ReadBuildCreationArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.Artifacts[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return releasedomain.Artifact{ID: id, TenantID: tenant}, nil
}
func (r memoryReleaseCatalogRepository) ReadReleaseTransitionScope(ctx context.Context, tenant, id string) (releaseapp.ReleaseTransitionScope, error) {
	v, err := r.ReadCandidateRelease(ctx, tenant, id)
	if err != nil {
		return releaseapp.ReleaseTransitionScope{}, err
	}
	return releaseapp.ReleaseTransitionScope(v), nil
}
func (r memoryReleaseCatalogRepository) ReadCandidateRelease(ctx context.Context, tenant, id string) (releaseapp.CandidateReleaseCoordinates, error) {
	var out releaseapp.CandidateReleaseCoordinates
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: id})
		if err != nil {
			return err
		}
		out = releaseapp.CandidateReleaseCoordinates{ID: id, TenantID: tenant, ProductID: refs.ProductID}
		return nil
	})
	if err != nil {
		return releaseapp.CandidateReleaseCoordinates{}, err
	}
	return out, nil
}
func (r memoryReleaseCatalogRepository) ReadCandidateTransitionScope(ctx context.Context, tenant, id string) (releaseapp.CandidateTransitionScope, error) {
	var out releaseapp.CandidateTransitionScope
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.ReleaseCandidates[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: v.ReleaseID})
		if err != nil {
			return err
		}
		out = releaseapp.CandidateTransitionScope{ID: id, TenantID: tenant, ReleaseID: v.ReleaseID, ProductID: refs.ProductID}
		return nil
	})
	if err != nil {
		return releaseapp.CandidateTransitionScope{}, err
	}
	return out, nil
}
func (r memoryReleaseCatalogRepository) ReadCandidateState(ctx context.Context, tenant, id string) (releaseapp.CandidateStateRow, error) {
	var out releaseapp.CandidateStateRow
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.ReleaseCandidates[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: v.ReleaseID})
		if err != nil {
			return err
		}
		candidate, err := memoryCandidateMetadata(v)
		if err != nil {
			return ErrConflict
		}
		out = releaseapp.CandidateStateRow{Candidate: candidate, ProductID: refs.ProductID}
		return nil
	})
	if err != nil {
		return releaseapp.CandidateStateRow{}, err
	}
	return out, nil
}

var (
	_ releaseapp.BuildIdentityReader            = memoryReleaseCatalogRepository{}
	_ releaseapp.BuildCreationGuardReader       = memoryReleaseCatalogRepository{}
	_ releaseapp.ReleaseTransitionGuardReader   = memoryReleaseCatalogRepository{}
	_ releaseapp.CandidateReleaseReader         = memoryReleaseCatalogRepository{}
	_ releaseapp.CandidateTransitionGuardReader = memoryReleaseCatalogRepository{}
	_ releaseapp.CandidateStateReader           = memoryReleaseCatalogRepository{}
)
