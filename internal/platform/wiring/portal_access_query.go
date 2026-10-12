package wiring

import packagequery "github.com/aatuh/evydence/internal/package/query"

// BuildPortalAccessQuery binds grant-filtered customer portal metadata reads
// to a durable reader that never selects token hashes.
func BuildPortalAccessQuery(reader packagequery.PortalAccessReader) (*packagequery.PortalAccess, error) {
	return packagequery.NewPortalAccess(reader)
}
