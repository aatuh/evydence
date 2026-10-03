package wiring

import (
	"time"

	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

// BuildSourceRepositoryQuery binds tenant-scoped, grant-filtered durable pages
// to the integration-owned read service.
func BuildSourceRepositoryQuery(reader integrationquery.SourceRepositoryReader) (*integrationquery.SourceRepositories, error) {
	return integrationquery.NewSourceRepositories(reader)
}

// BuildCollectorQuery binds tenant-scoped durable inventory to the
// integration-owned authorization service.
func BuildCollectorQuery(reader integrationquery.CollectorReader) (*integrationquery.Collectors, error) {
	return integrationquery.NewCollectors(reader)
}

// BuildCollectorHealthQuery binds the tenant-scoped point reader and clock.
func BuildCollectorHealthQuery(reader integrationquery.CollectorHealthReader) (*integrationquery.CollectorHealth, error) {
	return integrationquery.NewCollectorHealth(reader, time.Now)
}
