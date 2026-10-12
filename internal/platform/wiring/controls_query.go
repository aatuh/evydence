package wiring

import riskquery "github.com/aatuh/evydence/internal/risk/query"

// BuildControlsQuery binds risk-owned read policy to tenant-filtered durable
// framework pages and control points.
func BuildControlsQuery(reader riskquery.ControlsReader) (*riskquery.Controls, error) {
	return riskquery.NewControls(reader)
}
