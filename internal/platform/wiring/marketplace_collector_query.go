package wiring

import (
	"time"

	experimentalquery "github.com/aatuh/evydence/internal/experimental/query"
)

// BuildMarketplaceCollectorQuery binds experimental package metadata reads to
// tenant-filtered durable storage. Local memory keeps the Ledger fallback.
func BuildMarketplaceCollectorQuery(reader experimentalquery.MarketplaceCollectorReader) (*experimentalquery.MarketplaceCollectors, error) {
	return experimentalquery.NewMarketplaceCollectors(reader, time.Now)
}
