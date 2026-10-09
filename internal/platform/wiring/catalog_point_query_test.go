package wiring

import (
	"context"
	"testing"

	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type catalogPointReaderStub struct{}

func (catalogPointReaderStub) GetProject(context.Context, string, string) (releasedomain.Project, error) {
	return releasedomain.Project{}, nil
}

func (catalogPointReaderStub) GetRelease(context.Context, string, string) (releasedomain.Release, error) {
	return releasedomain.Release{}, nil
}

func TestBuildCatalogPointQueryRequiresReader(t *testing.T) {
	if _, err := BuildCatalogPointQuery(nil); err == nil {
		t.Fatal("query service accepted a missing database reader")
	}
	query, err := BuildCatalogPointQuery(catalogPointReaderStub{})
	if err != nil || query == nil {
		t.Fatalf("compose catalog point query=%T error=%v", query, err)
	}
}
