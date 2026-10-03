package wiring

import integrationquery "github.com/aatuh/evydence/internal/integration/query"

// BuildCommercialCollectorQuery binds tenant-scoped integration definitions
// to a durable reader rather than the Ledger compatibility snapshot.
func BuildCommercialCollectorQuery(reader integrationquery.CommercialCollectorReader) (*integrationquery.CommercialCollectors, error) {
	return integrationquery.NewCommercialCollectors(reader)
}
