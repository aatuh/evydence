package repositories

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

var _ releaseapp.ProductSlugReader = releaseCatalog{}

func (r releaseCatalog) ProductSlugExists(ctx context.Context, tenant, slug string) (bool, error) {
	tenant, slug = strings.TrimSpace(tenant), strings.TrimSpace(slug)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, tenant); err != nil {
		return false, err
	}
	if slug == "" || len(slug) > 1024 || !utf8.ValidString(slug) || strings.ContainsRune(slug, 0) {
		return false, app.ErrValidation
	}
	// Serialize absent slugs with the same fence-before-row ordering as other
	// focused writes. Never transfer existing product names or timestamps.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return false, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR KEY SHARE`, tenant); err != nil {
		return false, err
	}
	var exists bool
	if err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM products WHERE tenant_id=$1 AND slug=$2)`, tenant, slug).Scan(&exists); err != nil {
		return false, fmt.Errorf("read product slug existence: %w", err)
	}
	return exists, nil
}
