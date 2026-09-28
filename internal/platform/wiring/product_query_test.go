package wiring

import (
	"context"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type productPageReaderStub struct{}

func (productPageReaderStub) PageProducts(context.Context, releasequery.ProductPageRequest) (appquery.Result[releasedomain.Product], error) {
	return appquery.Result[releasedomain.Product]{}, nil
}

func (productPageReaderStub) GetProduct(context.Context, string, string) (releasedomain.Product, error) {
	return releasedomain.Product{}, nil
}

func TestBuildProductQueryRequiresReader(t *testing.T) {
	if _, err := BuildProductQuery(nil); err == nil {
		t.Fatal("query service accepted a missing database reader")
	}
	query, err := BuildProductQuery(productPageReaderStub{})
	if err != nil || query == nil {
		t.Fatalf("compose product query=%T error=%v", query, err)
	}
}
