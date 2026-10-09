package app

import (
	"context"

	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func (r memoryBuildRepository) LockCollectorWrites(ctx context.Context, tenant string) error {
	return memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(*MemoryUnitOfWorkSnapshot) error { return nil })
}

// Current coordinate-only release references, never collector credentials,
// detached signature text or raw parsed evidence. No SQL lock/work claim.
func (r memoryBuildRepository) ReadCollectorReleaseReference(ctx context.Context, tenant, kind, id string) (integrationapp.CollectorReference, error) {
	var out integrationapp.CollectorReference
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		out = integrationapp.CollectorReference{ID: id, TenantID: tenant, Type: kind}
		switch kind {
		case "collector":
			v, ok := s.Collectors[id]
			if !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
		case "signature":
			v, ok := s.ArtifactSignatures[id]
			if !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
			if !memoryGovernanceText(v.ArtifactID, 1024) || !memoryGovernanceText(v.SubjectDigest, 71) {
				return ErrConflict
			}
			a, ok := s.Artifacts[v.ArtifactID]
			if !ok || a.ID != v.ArtifactID || a.TenantID != tenant || a.Digest != v.SubjectDigest {
				return ErrNotFound
			}
			out.Digest = v.SubjectDigest
		case "sbom":
			v, ok := s.SBOMs[id]
			if !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
			_, err := memoryDecisionParsedOwner(s, tenant, v.EvidenceID, "sbom", v.ReleaseID, v.ArtifactID)
			return err
		case "scan":
			v, ok := s.VulnerabilityScans[id]
			if !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
			_, err := memoryDecisionParsedOwner(s, tenant, v.EvidenceID, "vulnerability_scan", v.ReleaseID, "")
			return err
		default:
			return ErrValidation
		}
		return nil
	})
	if err != nil {
		return integrationapp.CollectorReference{}, err
	}
	return out, nil
}
