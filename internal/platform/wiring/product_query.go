package wiring

import (
	"github.com/aatuh/evydence/internal/app"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildProductPageQuery binds a focused database reader to the existing
// authorization policy while the production compatibility Ledger is retired.
func BuildProductPageQuery(reader releasequery.ProductPageReader, ledger *app.Ledger) (*releasequery.Products, error) {
	if reader == nil {
		return nil, app.ErrValidation
	}
	authorizer, err := app.NewContextAuthorizer(ledger)
	if err != nil {
		return nil, err
	}
	return releasequery.NewProducts(reader, authorizer)
}
