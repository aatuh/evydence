package wiring

import (
	"context"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

type deploymentListReaderStub struct{}

func (deploymentListReaderStub) PageDeploymentEnvironments(context.Context, operationsquery.EnvironmentPageRequest) (appquery.Result[operationsdomain.DeploymentEnvironment], error) {
	return appquery.Result[operationsdomain.DeploymentEnvironment]{}, nil
}

func (deploymentListReaderStub) PageDeployments(context.Context, operationsquery.DeploymentPageRequest) (appquery.Result[operationsquery.DeploymentPoint], error) {
	return appquery.Result[operationsquery.DeploymentPoint]{}, nil
}

func TestBuildDeploymentListQueryRequiresReader(t *testing.T) {
	if _, err := BuildDeploymentListQuery(nil); err == nil {
		t.Fatal("deployment list query accepted a missing durable reader")
	}
	query, err := BuildDeploymentListQuery(deploymentListReaderStub{})
	if err != nil || query == nil {
		t.Fatalf("compose deployment list query=%T error=%v", query, err)
	}
}
