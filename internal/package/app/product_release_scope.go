package app

import (
	"strings"

	"github.com/aatuh/evydence/internal/application"
)

const MaxProductReleaseIDBytes = 1024

// Raw bounds precede trimming; an inferred release parent never adds a
// submitted product coordinate to a generated record or selection filter.
func NormalizeProductReleaseIDs(product, release string) (string, string, error) {
	if !graphText(product, MaxProductReleaseIDBytes) || !graphText(release, MaxProductReleaseIDBytes) {
		return product, release, ErrValidation
	}
	product, release = strings.TrimSpace(product), strings.TrimSpace(release)
	if product == "" && release == "" {
		return product, release, ErrValidation
	}
	return product, release, nil
}

func ValidateProductReleaseScope(tenant, product, release, scopeTenant string, r application.ResourceReferences) error {
	if !graphID(tenant) || scopeTenant != tenant || !graphID(r.ProductID) || r.ReleaseID != release || r.ReleaseID != "" && !graphID(r.ReleaseID) || r != (application.ResourceReferences{ProductID: r.ProductID, ReleaseID: release}) || product != "" && r.ProductID != product {
		return ErrNotFound
	}
	return nil
}
