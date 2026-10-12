package wiring

import (
	"time"

	application "github.com/aatuh/evydence/internal/application"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildEvidenceFlowQuery binds the release workflow to one tenant-scoped
// database aggregate statement and current actor-grant policy.
func BuildEvidenceFlowQuery(reader releasequery.EvidenceFlowReader) (*releasequery.EvidenceFlows, error) {
	return releasequery.NewEvidenceFlows(reader, releasequery.NewCatalogAuthorizer(), application.ClockFunc(time.Now))
}
