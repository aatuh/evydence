package wiring

import (
	"context"
	"testing"

	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

type deploymentPointReaderStub struct{}

func (deploymentPointReaderStub) GetDeploymentPoint(context.Context, string, string) (operationsquery.DeploymentPoint, error) {
	return operationsquery.DeploymentPoint{Deployment: operationsdomain.DeploymentEvent{}}, nil
}

func TestBuildDeploymentPointQueryRequiresReader(t *testing.T) {
	if _, err := BuildDeploymentPointQuery(nil); err == nil {
		t.Fatal("query service accepted a missing database reader")
	}
	query, err := BuildDeploymentPointQuery(deploymentPointReaderStub{})
	if err != nil || query == nil {
		t.Fatalf("compose deployment point query=%T error=%v", query, err)
	}
}
