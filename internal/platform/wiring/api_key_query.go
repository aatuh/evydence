package wiring

import identityquery "github.com/aatuh/evydence/internal/identity/query"

// BuildAPIKeyQuery binds tenant-authorized inventory reads to durable storage.
func BuildAPIKeyQuery(reader identityquery.APIKeyReader) (*identityquery.APIKeys, error) {
	return identityquery.NewAPIKeys(reader)
}
