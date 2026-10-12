package wiring

import (
	"time"

	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

// BuildMetricsQuery binds tenant-scoped, snapshot-consistent operational
// counters without loading the compatibility Ledger.
func BuildMetricsQuery(reader operationsquery.MetricsReader) (*operationsquery.Metrics, error) {
	return operationsquery.NewMetrics(reader, time.Now)
}
