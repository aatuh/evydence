package wiring

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
)

// packageCanonicalizer binds package hash ports to the existing normalized
// JSON profile and exact-byte SHA-256, without a Ledger compatibility adapter.
type packageCanonicalizer struct{}

func (packageCanonicalizer) HashPackageManifest(ctx context.Context, manifest map[string]any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(manifest)
}
func (packageCanonicalizer) HashPackageBytes(ctx context.Context, body []byte) (string, error) {
	return (htmlReportBytesHasher{}).HashPackageBytes(ctx, body)
}
