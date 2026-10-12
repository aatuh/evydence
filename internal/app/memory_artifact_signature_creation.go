package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	releasequery "github.com/aatuh/evydence/internal/release/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

var _ verificationapp.ArtifactSignatureCreationReader = memorySupplyChainRepository{}
var _ releasequery.ArtifactPointReader = memorySupplyChainRepository{}

// Transaction-snapshot ownership models the native fence/share-lock results,
// not actual PostgreSQL coordination, row locks or durability.
func (r memorySupplyChainRepository) LockArtifactSignatureCreationScope(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	var out application.ResourceReferences
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		a, ok := s.Artifacts[id]
		if !ok || a.ID != id || a.TenantID != tenant {
			return ErrNotFound
		}
		out = application.ResourceReferences{ArtifactID: id}
		return nil
	})
	if err != nil {
		return application.ResourceReferences{}, err
	}
	return out, nil
}

func (r memorySupplyChainRepository) LockSignatureArtifact(ctx context.Context, tenant, id string) (verificationapp.SignatureArtifact, error) {
	var out verificationapp.SignatureArtifact
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		a, ok := s.Artifacts[id]
		if !ok || a.ID != id || a.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryGovernanceText(a.Digest, 1024) {
			return ErrConflict
		}
		out = verificationapp.SignatureArtifact{ID: id, TenantID: tenant, Digest: a.Digest}
		return nil
	})
	if err != nil {
		return verificationapp.SignatureArtifact{}, err
	}
	return out, nil
}

// The native Supply Chain grant reader projects only identity/visibility.
func (r memorySupplyChainRepository) GetArtifactPoint(ctx context.Context, req releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	return memoryReleaseCatalogRepository(r).readArtifactPoint(ctx, req, false)
}
