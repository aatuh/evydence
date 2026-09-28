package wiring

import operationsquery "github.com/aatuh/evydence/internal/operations/query"

// BuildDeploymentPointQuery binds an operations-owned deployment read to one
// tenant-scoped database projection.
func BuildDeploymentPointQuery(reader operationsquery.DeploymentPointReader) (*operationsquery.DeploymentPoints, error) {
	return operationsquery.NewDeploymentPoints(reader)
}
