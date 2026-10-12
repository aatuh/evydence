package wiring

import (
	"time"

	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// BuildControlCoverageQuery binds the same bounded durable projection to
// control coverage and CRA readiness reports.
func BuildControlCoverageQuery(reader packagequery.ControlCoverageReader) (*packagequery.ControlCoverageReport, error) {
	return packagequery.NewControlCoverageReport(reader, time.Now)
}
