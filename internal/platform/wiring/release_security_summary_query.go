package wiring

import (
	"time"

	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func BuildReleaseSecuritySummaryQuery(reader riskquery.ReleaseSecuritySummaryReader) (*riskquery.ReleaseSecuritySummary, error) {
	return riskquery.NewReleaseSecuritySummary(reader, time.Now)
}
