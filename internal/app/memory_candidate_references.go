package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

// Candidate reference validation reads identities and source bindings only,
// never parsed components, findings, payloads or private descriptive metadata.
func (r memoryReleaseCatalogRepository) ValidateReleaseCandidateReferences(ctx context.Context, tenant, release string, refs releaseapp.ReleaseCandidateReferences) error {
	if !releaseapp.ValidCandidateReferences(refs) {
		return ErrValidation
	}
	return memoryGovernanceRead(ctx, r.uow, tenant, release, func(s *MemoryUnitOfWorkSnapshot) error {
		parent, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: release})
		if err != nil {
			return err
		}
		for _, id := range refs.BuildIDs {
			current, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{BuildID: id})
			if err != nil || current.ReleaseID != release {
				return ErrNotFound
			}
		}
		for _, id := range refs.ArtifactIDs {
			v, ok := s.Artifacts[id]
			if !ok || v.ID != id || v.TenantID != tenant {
				return ErrNotFound
			}
		}
		for _, group := range []struct {
			kind string
			ids  []string
		}{{"sbom", refs.SBOMIDs}, {"vulnerability_scan", refs.ScanIDs}, {"vex", refs.VEXIDs}, {"openapi_contract", refs.ContractIDs}, {"release_bundle", refs.BundleIDs}} {
			for _, id := range group.ids {
				if err := ctx.Err(); err != nil {
					return err
				}
				if !memoryCandidateReferenceOwned(s, tenant, release, parent.ProductID, group.kind, id) {
					return ErrNotFound
				}
			}
		}
		return nil
	})
}
func memoryCandidateReferenceOwned(s *MemoryUnitOfWorkSnapshot, tenant, release, product, kind, id string) bool {
	var evidence, owner, sourceRelease string
	switch kind {
	case "sbom":
		v, ok := s.SBOMs[id]
		if !ok || v.ID != id {
			return false
		}
		evidence, owner, sourceRelease = v.EvidenceID, v.TenantID, v.ReleaseID
	case "vulnerability_scan":
		v, ok := s.VulnerabilityScans[id]
		if !ok || v.ID != id {
			return false
		}
		evidence, owner, sourceRelease = v.EvidenceID, v.TenantID, v.ReleaseID
	case "vex":
		v, ok := s.VEXDocuments[id]
		if !ok || v.ID != id {
			return false
		}
		evidence, owner, sourceRelease = v.EvidenceID, v.TenantID, v.ReleaseID
	case "openapi_contract":
		v, ok := s.OpenAPIContracts[id]
		if !ok || v.ID != id || v.ProductID != product {
			return false
		}
		evidence, owner, sourceRelease = v.EvidenceID, v.TenantID, v.ReleaseID
	case "release_bundle":
		v, ok := s.ReleaseBundles[id]
		return ok && v.ID == id && v.TenantID == tenant && v.ReleaseID == release
	default:
		return false
	}
	e, ok := s.Evidence[evidence]
	return owner == tenant && sourceRelease == release && ok && e.ID == evidence && e.TenantID == tenant && e.ReleaseID == release && e.Type == kind
}

var _ releaseapp.ReleaseCandidateReferenceValidator = memoryReleaseCatalogRepository{}
