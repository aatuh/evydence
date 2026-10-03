package wiring

import (
	"time"

	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

// BuildRetentionQuery binds tenant-scoped, snapshot-consistent retention rows.
func BuildRetentionQuery(reader operationsquery.RetentionReader) (*operationsquery.RetentionReport, error) {
	return operationsquery.NewRetentionReport(reader, time.Now)
}
