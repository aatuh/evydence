package wiring

import operationsquery "github.com/aatuh/evydence/internal/operations/query"

// BuildDeploymentPointQuery binds an operations-owned deployment read to one
// tenant-scoped database projection.
func BuildDeploymentPointQuery(reader operationsquery.DeploymentPointReader) (*operationsquery.DeploymentPoints, error) {
	return operationsquery.NewDeploymentPoints(reader)
}

// BuildDeploymentListQuery binds SQL-side grant filtering and bounded keyset
// pages for deployment environments and events.
func BuildDeploymentListQuery(reader operationsquery.DeploymentListReader) (*operationsquery.DeploymentLists, error) {
	return operationsquery.NewDeploymentLists(reader)
}
