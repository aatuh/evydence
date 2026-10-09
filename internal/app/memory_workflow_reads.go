package app

import (
	"context"
	"errors"

	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

var _ riskapp.VulnerabilityWorkflowReader = memoryRiskRepository{}

// Workflow authority needs identifiers, not vulnerability statements, SBOM
// context or historical reasons. Preserve the scan's declared release, even
// when its source evidence records a release. This memory test adapter checks
// a transaction snapshot; it does not provide PostgreSQL row locks.
func (r memoryRiskRepository) ReadWorkflowFinding(ctx context.Context, tenant, id string) (riskapp.GovernanceSubjectReference, error) {
	var value riskapp.GovernanceSubjectReference
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(state *MemoryUnitOfWorkSnapshot) error {
		count := 0
		for key, scan := range state.VulnerabilityScans {
			if scan.TenantID != tenant || scan.ID != key {
				continue
			}
			for _, finding := range scan.Findings {
				if finding.ID != id {
					continue
				}
				source, err := memoryGovernanceEvidence(state, tenant, scan.EvidenceID, "vulnerability_scan")
				if errors.Is(err, ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if !memoryGovernanceText(scan.ReleaseID, 1024) {
					return ErrValidation
				}
				product := source.ProductID
				if scan.ReleaseID != "" {
					parent, ok := state.Releases[scan.ReleaseID]
					if !ok || parent.ID != scan.ReleaseID || parent.TenantID != tenant || source.ReleaseID != "" && source.ReleaseID != scan.ReleaseID || product != "" && product != parent.ProductID {
						continue
					}
					owner, err := memoryGovernanceProductRelease(state, tenant, parent.ProductID, scan.ReleaseID)
					if errors.Is(err, ErrNotFound) {
						continue
					}
					if err != nil {
						return err
					}
					product = owner.ProductID
				}
				count++
				if count > 1 {
					return ErrConflict
				}
				value = riskapp.GovernanceSubjectReference{TenantID: tenant, Type: "finding", ID: id, ProductID: product, ReleaseID: scan.ReleaseID}
			}
		}
		if count == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return riskapp.GovernanceSubjectReference{}, err
	}
	return value, nil
}
