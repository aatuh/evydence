package wiring

import (
	"time"

	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func BuildReleaseReadinessReportQuery(reader packagequery.ReleaseReadinessReportReader) (*packagequery.ReleaseReadinessReport, error) {
	return packagequery.NewReleaseReadinessReport(reader, time.Now)
}
