package app

import (
	"context"
	"slices"
	"strings"

	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

var _ operationsquery.DeploymentPointReader = memoryDeploymentRepository{}

// GetDeploymentPoint models the native point's current deployment/environment/
// release/product agreement in one locked typed snapshot. It does not select
// parent metadata or establish SQL transfer/work, row locks or durability.
func (r memoryDeploymentRepository) GetDeploymentPoint(ctx context.Context, tenant, id string) (operationsquery.DeploymentPoint, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return operationsquery.DeploymentPoint{}, operationsquery.ErrNotFound
	}
	var out operationsquery.DeploymentPoint
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		deployment, ok := s.DeploymentEvents[id]
		if !ok || deployment.ID != id || deployment.TenantID != tenant {
			return operationsquery.ErrNotFound
		}
		environment, ok := s.DeploymentEnvironments[deployment.EnvironmentID]
		if !ok || environment.ID != deployment.EnvironmentID || environment.TenantID != tenant || environment.ProductID == "" {
			return operationsquery.ErrNotFound
		}
		release, ok := s.Releases[deployment.ReleaseID]
		if !ok || release.ID != deployment.ReleaseID || release.TenantID != tenant || release.ProductID != environment.ProductID {
			return operationsquery.ErrNotFound
		}
		product, ok := s.Products[environment.ProductID]
		if !ok || product.ID != environment.ProductID || product.TenantID != tenant {
			return operationsquery.ErrNotFound
		}
		value := operationsdomain.DeploymentEvent(deployment)
		value.ArtifactIDs = slices.Clone(deployment.ArtifactIDs)
		value.FinishedAt = cloneTimePtr(deployment.FinishedAt)
		out = operationsquery.DeploymentPoint{Deployment: value, ProductID: product.ID}
		return ctx.Err()
	})
	if err != nil {
		return operationsquery.DeploymentPoint{}, err
	}
	return out, nil
}
