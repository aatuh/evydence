package app

import "context"

// Current artifact identity only; the typed model does not acquire SQL locks
// or read descriptive fields and digests during creation preflight.
func (r memoryEvidenceRepository) LockCreationArtifactIdentity(ctx context.Context, tenant, id string) error {
	return memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		artifact, ok := s.Artifacts[id]
		if !ok || artifact.ID != id || artifact.TenantID != tenant {
			return ErrNotFound
		}
		return nil
	})
}
