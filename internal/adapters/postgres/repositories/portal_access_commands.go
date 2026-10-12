package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var _ packageapp.PortalAccessWriteReader = identity{}

func (r identity) ReadPortalPackageScope(ctx context.Context, tenant, id string) (packageapp.PortalPackageScope, error) {
	var s packageapp.PortalPackageScope
	if ctx == nil {
		return s, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return s, err
	}
	for _, v := range []string{tenant, id} {
		canonical, err := packageapp.NormalizePortalAccessID(v)
		if err != nil || canonical != v {
			return s, app.ErrValidation
		}
	}
	root, err := (futureExtensions(r)).ReadEvidenceSummaryScope(ctx, tenant, "customer_package", id)
	if err != nil {
		return s, mapPackageDraftRepositoryError(err)
	}
	s = packageapp.PortalPackageScope{TenantID: tenant, PackageID: id, Resources: root.Resources}
	return s, packageapp.ValidatePortalPackageScope(tenant, id, s)
}
func (r identity) ReadPortalAccessForRevocation(ctx context.Context, tenant, id string) (packagedomain.CustomerPortalAccess, error) {
	return r.readPortalAccess(ctx, tenant, id, false)
}
func (r identity) ReadPortalAccessForToken(ctx context.Context, tenant, id string) (packagedomain.CustomerPortalAccess, error) {
	return r.readPortalAccess(ctx, tenant, id, true)
}

// Administrators never read a token hash. Token verification selects only one
// bounded credential row; unrelated rows and package manifests are excluded.
func (r identity) readPortalAccess(ctx context.Context, tenant, id string, credential bool) (packagedomain.CustomerPortalAccess, error) {
	var empty packagedomain.CustomerPortalAccess
	if ctx == nil {
		return empty, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if _, err := packageapp.NormalizePortalAccessID(tenant); err != nil {
		return empty, err
	}
	if _, err := packageapp.NormalizePortalAccessID(id); err != nil {
		return empty, err
	}
	hash, hashBound := "''", "false"
	if credential {
		hash, hashBound = "left(hash,65)", "octet_length(hash)>64"
	}
	var v packagedomain.CustomerPortalAccess
	var oversized bool
	v.TenantID = tenant
	statement := `SELECT left(id,1025),left(package_id,1025),left(customer_name,641),left(coalesce(reviewer_name,''),641),left(coalesce(reviewer_email,''),641),require_nda,nda_accepted_at,left(coalesce(nda_accepted_by,''),641),left(coalesce(watermark,''),641),left(prefix,13),expires_at,revoked_at,access_count,failed_access_count,last_accessed_at,last_failed_at,left(schema_version,1025),created_at,` + hash + `,
(octet_length(id)>1024 OR octet_length(package_id)>1024 OR octet_length(customer_name)>640 OR coalesce(octet_length(reviewer_name)>640,false) OR coalesce(octet_length(reviewer_email)>640,false) OR coalesce(octet_length(nda_accepted_by)>640,false) OR coalesce(octet_length(watermark)>640,false) OR octet_length(prefix)>12 OR octet_length(schema_version)>1024 OR ` + hashBound + `)
FROM customer_portal_access WHERE tenant_id=$1 AND id=$2 FOR UPDATE`
	err := r.tx.QueryRow(ctx, statement, tenant, id).Scan(&v.ID, &v.PackageID, &v.CustomerName, &v.ReviewerName, &v.ReviewerEmail, &v.RequireNDA, &v.NDAAcceptedAt, &v.NDAAcceptedBy, &v.Watermark, &v.Prefix, &v.ExpiresAt, &v.RevokedAt, &v.AccessCount, &v.FailedAccessCount, &v.LastAccessedAt, &v.LastFailedAt, &v.SchemaVersion, &v.CreatedAt, &v.Hash, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, app.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read selected portal access: %w", err)
	}
	if oversized || v.AccessCount < 0 || v.FailedAccessCount < 0 {
		return empty, app.ErrConflict
	}
	return v, nil
}
func (r identity) InsertFocusedPortalAccess(ctx context.Context, v packagedomain.CustomerPortalAccess) error {
	if err := packageapp.ValidatePortalAccessCreation(v); err != nil {
		return err
	}
	if _, err := r.ReadPortalPackageScope(ctx, v.TenantID, v.PackageID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `INSERT INTO customer_portal_access(id,tenant_id,package_id,customer_name,reviewer_name,reviewer_email,prefix,hash,expires_at,require_nda,watermark,schema_version,created_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, v.ID, v.TenantID, v.PackageID, v.CustomerName, nullableString(v.ReviewerName), nullableString(v.ReviewerEmail), v.Prefix, v.Hash, v.ExpiresAt, v.RequireNDA, v.Watermark, v.SchemaVersion, v.CreatedAt)
	return writeError("insert focused portal access", err)
}
func (r identity) RevokeFocusedPortalAccess(ctx context.Context, tenant, id string, at time.Time) error {
	if _, err := packageapp.NormalizePortalAccessID(tenant); err != nil {
		return err
	}
	if _, err := packageapp.NormalizePortalAccessID(id); err != nil {
		return err
	}
	if at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `UPDATE customer_portal_access SET revoked_at=$3 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, tenant, id, at)
	if err != nil {
		return writeError("revoke selected portal access", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r identity) UpdateFocusedPortalTokenAccess(ctx context.Context, previous, current packagedomain.CustomerPortalAccess) error {
	if err := packageapp.ValidatePortalTokenTransition(previous, current); err != nil {
		return err
	}
	result, err := r.tx.Exec(ctx, `UPDATE customer_portal_access SET revoked_at=$3,access_count=$4,failed_access_count=$5,last_accessed_at=$6,last_failed_at=$7,nda_accepted_at=$8,nda_accepted_by=$9
WHERE tenant_id=$1 AND id=$2 AND package_id=$10 AND prefix=$11 AND hash=$12
AND access_count=$13 AND failed_access_count=$14 AND revoked_at IS NOT DISTINCT FROM $15
AND nda_accepted_at IS NOT DISTINCT FROM $16 AND nda_accepted_by IS NOT DISTINCT FROM $17`, current.TenantID, current.ID, current.RevokedAt, current.AccessCount, current.FailedAccessCount, current.LastAccessedAt, current.LastFailedAt, current.NDAAcceptedAt, nullableString(current.NDAAcceptedBy), previous.PackageID, previous.Prefix, previous.Hash, previous.AccessCount, previous.FailedAccessCount, previous.RevokedAt, previous.NDAAcceptedAt, nullableString(previous.NDAAcceptedBy))
	if err != nil {
		return writeError("update selected portal lifecycle", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}
