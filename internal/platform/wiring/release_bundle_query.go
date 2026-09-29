package wiring

import packagequery "github.com/aatuh/evydence/internal/package/query"

// BuildReleaseBundleQuery binds the package-owned read policy to a durable
// point reader; local-memory mode retains its Ledger-backed path.
func BuildReleaseBundleQuery(reader packagequery.ReleaseBundleReader) (*packagequery.ReleaseBundles, error) {
	return packagequery.NewReleaseBundles(reader)
}
