package wiring

import riskquery "github.com/aatuh/evydence/internal/risk/query"

// BuildControlEvidenceQuery binds risk-owned read policy to bounded durable
// pages. Local memory deliberately continues through the Ledger fallback.
func BuildControlEvidenceQuery(reader riskquery.ControlEvidenceReader) (*riskquery.ControlEvidence, error) {
	return riskquery.NewControlEvidence(reader)
}
