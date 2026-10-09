package wiring

import packagequery "github.com/aatuh/evydence/internal/package/query"

// BuildReleaseBundleQuery binds the package-owned read policy to a durable
// point reader. PostgreSQL is required for the supported API runtime.
func BuildReleaseBundleQuery(reader packagequery.ReleaseBundleReader) (*packagequery.ReleaseBundles, error) {
	return packagequery.NewReleaseBundles(reader)
}
