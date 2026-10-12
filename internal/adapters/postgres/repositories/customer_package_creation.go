package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func customerCreationID(v string, optional bool) bool {
	return (optional || v != "") && v == strings.TrimSpace(v) && len(v) <= packageapp.MaxCustomerPackageIDBytes && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}

// Fence before locking only current ownership coordinates. No product names,
// release metadata, evidence, manifests, signing keys, or tenant state is read.
func (r packages) LockCustomerPackageCreationScope(ctx context.Context, tenant, product, release string) error {
	if ctx == nil || !customerCreationID(tenant, false) || !customerCreationID(product, false) || !customerCreationID(release, true) {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, product); err != nil {
		return err
	}
	if release != "" {
		return requireRow(ctx, r.tx, `SELECT 1 FROM releases WHERE tenant_id=$1 AND id=$2 AND product_id=$3 FOR SHARE`, tenant, release, product)
	}
	return nil
}

// Re-read and lock only the selected public policy. Oversized text and arrays
// are rejected before transfer, including null or individually oversized array
// items. The common writer fence precedes all tenant/policy locks.
func (r packages) GetCustomerPackageRedactionProfile(ctx context.Context, tenant, id string) (packagedomain.RedactionProfile, error) {
	var empty packagedomain.RedactionProfile
	if ctx == nil || !customerCreationID(tenant, false) || !customerCreationID(id, false) {
		return empty, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return empty, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return empty, err
	}
	p, _, err := readCustomerPackageRedactionProfile(ctx, r.tx, tenant, id, packageapp.MaxCustomerPackageManifestBytes, true)
	return p, err
}

// ReadCustomerPackageRedactionProfileSnapshot reads only the selected public
// policy in the caller's snapshot. It takes no writer fence or row lock. The
// returned byte count charges the complete JSON representation to the caller's
// shared budget. The write adapter uses the same bounded decoder with locks.
func ReadCustomerPackageRedactionProfileSnapshot(ctx context.Context, tx pgx.Tx, tenant, id string, maxBytes int) (packagedomain.RedactionProfile, int, error) {
	return readCustomerPackageRedactionProfile(ctx, tx, tenant, id, maxBytes, false)
}

func readCustomerPackageRedactionProfile(ctx context.Context, tx pgx.Tx, tenant, id string, maxBytes int, lock bool) (packagedomain.RedactionProfile, int, error) {
	var empty packagedomain.RedactionProfile
	if ctx == nil || tx == nil || !customerCreationID(tenant, false) || !customerCreationID(id, false) || maxBytes < 0 || maxBytes > packageapp.MaxCustomerPackageManifestBytes {
		return empty, 0, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, 0, err
	}
	rowLock := ""
	if lock {
		rowLock = " FOR SHARE"
	}
	rows, err := tx.Query(ctx, `WITH selected AS MATERIALIZED (
	 SELECT id,tenant_id,name,description,allowed_types,excluded_fields,schema_version,created_at,
	 `+customerProfileArrayInvalidSQL("allowed_types")+` AS allowed_invalid,`+customerProfileArrayInvalidSQL("excluded_fields")+` AS excluded_invalid
	 FROM redaction_profiles WHERE tenant_id=$1 AND id=$2`+rowLock+`
	), projected AS (
	 SELECT jsonb_build_object('ID',id,'TenantID',tenant_id,'Name',name,'Description',coalesce(description,''),
	 'AllowedTypes',CASE WHEN allowed_invalid THEN '[]'::jsonb ELSE to_jsonb(allowed_types) END,
	 'ExcludedFields',CASE WHEN excluded_invalid THEN '[]'::jsonb ELSE to_jsonb(excluded_fields) END,
	 'SchemaVersion',schema_version,'CreatedAt',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) AS metadata,
	 (octet_length(name)>65536 OR octet_length(coalesce(description,''))>65536 OR octet_length(schema_version)>1024
	 OR allowed_invalid OR excluded_invalid OR NOT isfinite(created_at) OR extract(year FROM created_at AT TIME ZONE 'UTC') NOT BETWEEN 1 AND 9999) AS invalid
	 FROM selected
	) SELECT CASE WHEN invalid OR octet_length(metadata::text)>$3 THEN NULL ELSE metadata END,
	 invalid OR octet_length(metadata::text)>$3 FROM projected`, tenant, id, maxBytes)
	if err != nil {
		return empty, 0, fmt.Errorf("read customer-package redaction policy: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return empty, 0, fmt.Errorf("iterate customer-package redaction policy: %w", err)
		}
		return empty, 0, app.ErrNotFound
	}
	var raw []byte
	var rejected bool
	if err := rows.Scan(&raw, &rejected); err != nil {
		return empty, 0, fmt.Errorf("scan customer-package redaction policy: %w", err)
	}
	var p packagedomain.RedactionProfile
	if rejected || len(raw) == 0 || len(raw) > maxBytes || json.Unmarshal(raw, &p) != nil {
		return empty, 0, app.ErrConflict
	}
	if rows.Next() {
		return empty, 0, app.ErrConflict
	}
	if err := rows.Err(); err != nil {
		return empty, 0, fmt.Errorf("iterate customer-package redaction policy: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return empty, 0, err
	}
	return p, len(raw), nil
}

// Check dimensions before array_position: PostgreSQL rejects that operation
// on multidimensional arrays. Limits are checked before building policy JSON.
func customerProfileArrayInvalidSQL(column string) string {
	return `(CASE WHEN coalesce(array_ndims(` + column + `)>1,false) OR cardinality(` + column + `)>1024 THEN true
	 ELSE array_position(` + column + `,NULL) IS NOT NULL OR EXISTS(SELECT 1 FROM unnest(` + column + `) v WHERE octet_length(v)>1024) END)`
}
