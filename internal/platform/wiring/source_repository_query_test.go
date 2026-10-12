package wiring

import (
	"context"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

type sourceRepositoryReaderStub struct{}

func (sourceRepositoryReaderStub) PageSourceRepositories(context.Context, integrationquery.SourceRepositoryPageRequest) (appquery.Result[integrationquery.SourceRepositoryPoint], error) {
	return appquery.Result[integrationquery.SourceRepositoryPoint]{}, nil
}

func TestBuildSourceRepositoryQueryRequiresReader(t *testing.T) {
	if _, err := BuildSourceRepositoryQuery(nil); err == nil {
		t.Fatal("source repository query accepted a missing durable reader")
	}
	query, err := BuildSourceRepositoryQuery(sourceRepositoryReaderStub{})
	if err != nil || query == nil {
		t.Fatalf("compose source repository query=%T error=%v", query, err)
	}
}
