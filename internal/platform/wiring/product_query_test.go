package wiring

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type productPageReaderStub struct{}

func (productPageReaderStub) PageProducts(context.Context, releasequery.ProductPageRequest) (appquery.Result[releasedomain.Product], error) {
	return appquery.Result[releasedomain.Product]{}, nil
}

func TestBuildProductPageQueryRequiresReaderAndAuthorizationBoundary(t *testing.T) {
	ledger := app.NewLedger(app.Config{})
	if _, err := BuildProductPageQuery(nil, ledger); err == nil {
		t.Fatal("query service accepted a missing database reader")
	}
	if _, err := BuildProductPageQuery(productPageReaderStub{}, nil); err == nil {
		t.Fatal("query service accepted a missing authorization boundary")
	}
	query, err := BuildProductPageQuery(productPageReaderStub{}, ledger)
	if err != nil || query == nil {
		t.Fatalf("compose product query=%T error=%v", query, err)
	}
}
