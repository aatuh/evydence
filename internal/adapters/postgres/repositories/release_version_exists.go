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

var _ releaseapp.ReleaseVersionReader = releaseCatalog{}

func (r releaseCatalog) ReleaseVersionExists(ctx context.Context, tenant, product, version string) (bool, error) {
	tenant, product, version = strings.TrimSpace(tenant), strings.TrimSpace(product), strings.TrimSpace(version)
	if err := validBuildIdentityRead(ctx, r.tx, tenant, product); err != nil {
		return false, err
	}
	if version == "" || len(version) > 65536 || !utf8.ValidString(version) || strings.ContainsRune(version, 0) {
		return false, app.ErrValidation
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return false, err
	}
	// Serialize absent version identities before insertion; an existing release
	// contributes only an existence bit, never lifecycle metadata or large text.
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM products WHERE tenant_id=$1 AND id=$2 FOR NO KEY UPDATE`, tenant, product); err != nil {
		return false, err
	}
	var exists bool
	if err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM releases WHERE tenant_id=$1 AND product_id=$2 AND version=$3)`, tenant, product, version).Scan(&exists); err != nil {
		return false, fmt.Errorf("read release version existence: %w", err)
	}
	return exists, nil
}
