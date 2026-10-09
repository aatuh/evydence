package app

import (
	"slices"

	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

// Match the native conservative prefilter, including inconsistent direct or
// inferred associations. It is not authority: selected coordinates and worker
// facts are rechecked before private metadata or page slots are supplied.
func memoryEvidenceCandidateVisible(s *MemoryUnitOfWorkSnapshot, e domain.EvidenceItem, in evidencequery.EvidencePageRequest) bool {
	if in.TenantWide {
		return true
	}
	product := func(id string) bool { return id != "" && slices.Contains(in.AllowedProductIDs, id) }
	project := func(id string) bool { return id != "" && slices.Contains(in.AllowedProjectIDs, id) }
	release := func(id string) bool { return id != "" && slices.Contains(in.AllowedReleaseIDs, id) }
	if product(e.ProductID) || project(e.ProjectID) || release(e.ReleaseID) {
		return true
	}
	if j, ok := s.Projects[e.ProjectID]; ok && j.TenantID == e.TenantID && product(j.ProductID) {
		return true
	}
	if r, ok := s.Releases[e.ReleaseID]; ok && r.TenantID == e.TenantID && product(r.ProductID) {
		return true
	}
	if b, ok := s.BuildRuns[e.BuildID]; ok && b.TenantID == e.TenantID {
		if project(b.ProjectID) || release(b.ReleaseID) {
			return true
		}
		if j, ok := s.Projects[b.ProjectID]; ok && j.TenantID == e.TenantID && product(j.ProductID) {
			return true
		}
	}
	if d, ok := s.DeploymentEvents[e.DeploymentID]; ok && d.TenantID == e.TenantID {
		if release(d.ReleaseID) {
			return true
		}
		if env, ok := s.DeploymentEnvironments[d.EnvironmentID]; ok && env.TenantID == e.TenantID && product(env.ProductID) {
			return true
		}
	}
	return false
}
