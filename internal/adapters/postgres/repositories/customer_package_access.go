package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// GetCustomerSecurityPackageForUpdate resolves current tenant-owned parents
// and locks only the selected package. Bound the manifest before transfer,
// rather than allocating an arbitrary stored JSON value in the API process.
func (r packages) GetCustomerSecurityPackageForUpdate(ctx context.Context, tenantID, id string) (domain.CustomerSecurityPackage, error) {
	var empty domain.CustomerSecurityPackage
	if ctx == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" {
		return empty, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	var pkg domain.CustomerSecurityPackage
	var manifest []byte
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT left(p.id,1025),p.tenant_id,left(p.product_id,1025),left(coalesce(p.release_id,''),1025),left(p.redaction_profile_id,1025),left(p.title,4097),left(p.state,65),
		CASE WHEN octet_length(p.manifest::text)<=$3 THEN p.manifest ELSE NULL END,
		left(p.manifest_hash,1025),p.expires_at,p.access_count,left(p.schema_version,1025),p.created_at,
		(octet_length(p.id)>1024 OR octet_length(p.product_id)>1024 OR octet_length(coalesce(p.release_id,''))>1024 OR octet_length(p.redaction_profile_id)>1024 OR octet_length(p.title)>4096 OR octet_length(p.state)>64 OR octet_length(p.manifest_hash)>1024 OR octet_length(p.schema_version)>1024 OR octet_length(p.manifest::text)>$3)
		FROM customer_security_packages AS p
		JOIN products AS product ON product.id=p.product_id AND product.tenant_id=p.tenant_id
		LEFT JOIN releases AS release ON release.id=p.release_id AND release.tenant_id=p.tenant_id AND release.product_id=p.product_id
		WHERE p.tenant_id=$1 AND p.id=$2 AND (coalesce(p.release_id,'')='' OR release.id IS NOT NULL)
		FOR UPDATE OF p`, tenantID, id, packageapp.MaxCustomerPackageManifestBytes).Scan(
		&pkg.ID, &pkg.TenantID, &pkg.ProductID, &pkg.ReleaseID, &pkg.RedactionProfileID, &pkg.Title, &pkg.State, &manifest, &pkg.ManifestHash, &pkg.ExpiresAt, &pkg.AccessCount, &pkg.SchemaVersion, &pkg.CreatedAt, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, app.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read locked customer package: %w", err)
	}
	if oversized || len(manifest) == 0 || json.Unmarshal(manifest, &pkg.Manifest) != nil || pkg.Manifest == nil {
		return empty, app.ErrConflict
	}
	return pkg, nil
}
