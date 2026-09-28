package wiring

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type catalogPointReaderStub struct{}

func (catalogPointReaderStub) GetProject(context.Context, string, string) (releasedomain.Project, error) {
	return releasedomain.Project{}, nil
}

func (catalogPointReaderStub) GetRelease(context.Context, string, string) (releasedomain.Release, error) {
	return releasedomain.Release{}, nil
}

func TestBuildCatalogPointQueryRequiresReaderAndAuthorizationBoundary(t *testing.T) {
	ledger := app.NewLedger(app.Config{})
	if _, err := BuildCatalogPointQuery(nil, ledger); err == nil {
		t.Fatal("query service accepted a missing database reader")
	}
	if _, err := BuildCatalogPointQuery(catalogPointReaderStub{}, nil); err == nil {
		t.Fatal("query service accepted a missing authorization boundary")
	}
	query, err := BuildCatalogPointQuery(catalogPointReaderStub{}, ledger)
	if err != nil || query == nil {
		t.Fatalf("compose catalog point query=%T error=%v", query, err)
	}
}
