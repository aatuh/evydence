package wiring

import (
	"github.com/aatuh/evydence/internal/app"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildProductQuery binds a focused database reader to the existing
// authorization policy while the production compatibility Ledger is retired.
func BuildProductQuery(reader releasequery.ProductReader, ledger *app.Ledger) (*releasequery.Products, error) {
	if reader == nil {
		return nil, app.ErrValidation
	}
	authorizer, err := app.NewContextAuthorizer(ledger)
	if err != nil {
		return nil, err
	}
	return releasequery.NewProducts(reader, authorizer)
}

// BuildCatalogPointQuery shares the current authorization policy with
// tenant-bound project and release point readers.
func BuildCatalogPointQuery(reader releasequery.CatalogPointReader, ledger *app.Ledger) (*releasequery.CatalogPoints, error) {
	if reader == nil {
		return nil, app.ErrValidation
	}
	authorizer, err := app.NewContextAuthorizer(ledger)
	if err != nil {
		return nil, err
	}
	return releasequery.NewCatalogPoints(reader, authorizer)
}
