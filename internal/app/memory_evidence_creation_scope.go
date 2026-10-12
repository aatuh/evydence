package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

// ResolveEvidenceCreationScope projects only current owned parent IDs in one
// test transaction. The same coordinate resolver is used by Operations reads;
// it does not inspect descriptive metadata or model PostgreSQL share locks.
func (r memoryEvidenceRepository) ResolveEvidenceCreationScope(ctx context.Context, tenant string, refs application.ResourceReferences) (application.ResourceReferences, error) {
	if refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID}) {
		return application.ResourceReferences{}, ErrValidation
	}
	var out application.ResourceReferences
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryOperationsCoordinates(s, tenant, refs)
		return err
	})
	if err != nil {
		return application.ResourceReferences{}, err
	}
	return out, nil
}

var _ evidencequery.EvidenceCreationScopeReader = memoryEvidenceRepository{}
