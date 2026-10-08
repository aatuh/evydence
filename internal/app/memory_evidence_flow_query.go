package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releasequery.EvidenceFlowReader = memoryReleaseCatalogRepository{}

// Test-backend counts use one current transaction view and never materialize
// evidence metadata or consult Ledger. Memory scans/whole-snapshot transactions
// are not PostgreSQL statement, transfer-budget or row-lock evidence.
func (r memoryReleaseCatalogRepository) ReadEvidenceFlowSnapshot(ctx context.Context, tenant, release string) (releasequery.EvidenceFlowSnapshot, error) {
	if !memoryMembershipQueryText(release, 1024) {
		return releasequery.EvidenceFlowSnapshot{}, releasequery.ErrValidation
	}
	var out releasequery.EvidenceFlowSnapshot
	err := r.catalogQueryRead(ctx, tenant, release, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: release})
		if err != nil {
			return err
		}
		counts := map[string]int{"artifact_refs": 0, "passed_builds": 0, "build_attestations": 0, "sboms": 0, "vulnerability_scans": 0, "vex_documents": 0, "vulnerability_decisions": 0, "release_bundles": 0, "customer_packages": 0}
		artifacts := make(map[string]struct{})
		addArtifact := func(id string) {
			if id != "" {
				artifacts[id] = struct{}{}
			}
		}
		for _, v := range s.SBOMs {
			if v.TenantID == tenant && v.ReleaseID == release {
				counts["sboms"]++
				addArtifact(v.ArtifactID)
			}
		}
		for _, v := range s.VulnerabilityScans {
			if v.TenantID == tenant && v.ReleaseID == release {
				counts["vulnerability_scans"]++
			}
		}
		for _, v := range s.VEXDocuments {
			if v.TenantID == tenant && v.ReleaseID == release {
				counts["vex_documents"]++
				addArtifact(v.ArtifactID)
			}
		}
		for _, v := range s.Decisions {
			if v.TenantID == tenant && v.ReleaseID == release && v.SupersededBy == "" {
				counts["vulnerability_decisions"]++
			}
		}
		for _, v := range s.BuildRuns {
			if v.TenantID != tenant || v.ReleaseID != release {
				continue
			}
			if v.Status == "passed" {
				counts["passed_builds"]++
			}
			for _, output := range v.Outputs {
				addArtifact(output.ArtifactID)
			}
		}
		for _, v := range s.BuildAttestations {
			b, ok := s.BuildRuns[v.BuildID]
			if ok && b.ID == v.BuildID && b.TenantID == tenant && v.TenantID == tenant && b.ReleaseID == release {
				counts["build_attestations"]++
			}
		}
		for _, v := range s.ReleaseBundles {
			if v.TenantID == tenant && v.ReleaseID == release {
				counts["release_bundles"]++
			}
		}
		for _, v := range s.CustomerPackages {
			if v.TenantID == tenant && v.ReleaseID == release {
				counts["customer_packages"]++
			}
		}
		counts["artifact_refs"] = len(artifacts)
		out = releasequery.EvidenceFlowSnapshot{TenantID: tenant, ReleaseID: release, ProductID: refs.ProductID, Counts: counts}
		return nil
	})
	if err != nil {
		return releasequery.EvidenceFlowSnapshot{}, err
	}
	return out, nil
}
