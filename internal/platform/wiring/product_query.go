package wiring

import (
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildProductQuery binds a tenant-scoped database reader to catalog policy
// without loading the compatibility Ledger for authorization.
func BuildProductQuery(reader releasequery.ProductReader) (*releasequery.Products, error) {
	return releasequery.NewProducts(reader, releasequery.NewCatalogAuthorizer())
}

// BuildCatalogPointQuery binds tenant-scoped project and release readers to
// the same catalog policy.
func BuildCatalogPointQuery(reader releasequery.CatalogPointReader) (*releasequery.CatalogPoints, error) {
	return releasequery.NewCatalogPoints(reader, releasequery.NewCatalogAuthorizer())
}

// BuildBuildPointQuery binds the build and its authorization coordinates to one
// tenant-scoped database projection.
func BuildBuildPointQuery(reader releasequery.BuildPointReader) (*releasequery.BuildPoints, error) {
	return releasequery.NewBuildPoints(reader, releasequery.NewCatalogAuthorizer())
}
