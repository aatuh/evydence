package app

import (
	"context"
	"strings"

	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

var (
	_ releaseapp.ArtifactRegistrationReader   = memoryReleaseCatalogRepository{}
	_ releaseapp.ContainerImageIdentityReader = memorySupplyChainRepository{}
)

// These test-backend readers use the current transaction snapshot. They do
// not prove PostgreSQL's absent-row serialization, transfer budgets or locks.
func (r memoryReleaseCatalogRepository) ArtifactIdentityByDigest(ctx context.Context, tenant, digest string) (releaseapp.ArtifactRegistrationIdentity, bool, error) {
	tenant, digest = strings.TrimSpace(tenant), strings.TrimSpace(digest)
	if !memoryMembershipQueryText(digest, 71) {
		return releaseapp.ArtifactRegistrationIdentity{}, false, ErrValidation
	}
	var out releaseapp.ArtifactRegistrationIdentity
	found := false
	err := memoryGovernanceRead(ctx, r.uow, tenant, digest, func(s *MemoryUnitOfWorkSnapshot) error {
		for key, v := range s.Artifacts {
			if v.TenantID != tenant || v.Digest != digest {
				continue
			}
			if v.ID != key || !memoryMembershipQueryText(v.ID, 1024) || found {
				return ErrConflict
			}
			out = releaseapp.ArtifactRegistrationIdentity{ID: v.ID, TenantID: v.TenantID, Digest: v.Digest}
			found = true
		}
		return nil
	})
	if err != nil {
		return releaseapp.ArtifactRegistrationIdentity{}, false, err
	}
	return out, found, nil
}

func (r memoryReleaseCatalogRepository) ReadArtifactMetadata(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	var out releasedomain.Artifact
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		v, ok := s.Artifacts[id]
		if !ok || v.ID != id || v.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryMembershipText(v.Name, 65536) || !memoryMembershipText(v.MediaType, 65536) || !memoryMembershipText(v.Digest, 71) || v.Size < 0 {
			return ErrConflict
		}
		out = releasedomain.Artifact{ID: v.ID, TenantID: v.TenantID, Name: v.Name, MediaType: v.MediaType, Digest: v.Digest, Size: v.Size, CreatedAt: v.CreatedAt.UTC()}
		return nil
	})
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	return out, nil
}

func (r memorySupplyChainRepository) ContainerImageRegistrationIdentityByKey(ctx context.Context, tenant, repository, digest string) (releaseapp.ContainerImageRegistrationIdentity, bool, error) {
	tenant, repository, digest = strings.TrimSpace(tenant), strings.TrimSpace(repository), strings.TrimSpace(digest)
	if !memoryMembershipQueryText(repository, 65536) || !memoryMembershipQueryText(digest, 71) {
		return releaseapp.ContainerImageRegistrationIdentity{}, false, ErrValidation
	}
	var out releaseapp.ContainerImageRegistrationIdentity
	found := false
	err := memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		for key, v := range s.ContainerImages {
			if v.TenantID != tenant || v.Repository != repository || v.Digest != digest {
				continue
			}
			if v.ID != key || !memoryMembershipQueryText(v.ID, 1024) || !memoryMembershipText(v.ArtifactID, 1024) || found {
				return ErrConflict
			}
			out = releaseapp.ContainerImageRegistrationIdentity{ID: v.ID, TenantID: v.TenantID, ArtifactID: v.ArtifactID}
			found = true
		}
		return nil
	})
	if err != nil {
		return releaseapp.ContainerImageRegistrationIdentity{}, false, err
	}
	return out, found, nil
}

func (r memorySupplyChainRepository) ContainerImageByRepositoryDigest(ctx context.Context, tenant, repository, digest string) (releasedomain.ContainerImage, bool, error) {
	tenant, repository, digest = strings.TrimSpace(tenant), strings.TrimSpace(repository), strings.TrimSpace(digest)
	if !memoryMembershipQueryText(repository, 65536) || !memoryMembershipQueryText(digest, 71) {
		return releasedomain.ContainerImage{}, false, ErrValidation
	}
	var out releasedomain.ContainerImage
	found := false
	err := memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		for key, v := range s.ContainerImages {
			if v.TenantID != tenant || v.Repository != repository || v.Digest != digest {
				continue
			}
			if v.ID != key || !memoryMembershipQueryText(v.ID, 1024) || !memoryMembershipText(v.ArtifactID, 1024) || !memoryMembershipText(v.Tag, 65536) || !memoryMembershipText(v.Platform, 65536) || !memoryMembershipText(v.SchemaVersion, 1024) || found {
				return ErrConflict
			}
			out = releasedomain.ContainerImage{ID: v.ID, TenantID: v.TenantID, ArtifactID: v.ArtifactID, Repository: v.Repository, Tag: v.Tag, Digest: v.Digest, Platform: v.Platform, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt.UTC()}
			found = true
		}
		return nil
	})
	if err != nil {
		return releasedomain.ContainerImage{}, false, err
	}
	return out, found, nil
}
