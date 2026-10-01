package wiring

import (
	"time"

	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

// BuildMissingEvidenceQuery joins the read-only risk evaluator to the package
// report renderer; the reader is the production PostgreSQL scoped projection.
func BuildMissingEvidenceQuery(reader riskquery.ReleaseReadinessReader) (*packagequery.MissingEvidenceReport, error) {
	readiness, err := riskquery.NewReleaseReadinessQuery(reader, time.Now)
	if err != nil {
		return nil, err
	}
	return packagequery.NewMissingEvidenceReport(readiness)
}
