package repositories

import (
	"context"
	"errors"
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
	p := packagedomain.RedactionProfile{ID: id, TenantID: tenant}
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT CASE WHEN octet_length(name)<=65536 THEN name ELSE '' END,
		CASE WHEN octet_length(coalesce(description,''))<=65536 THEN coalesce(description,'') ELSE '' END,
		CASE WHEN cardinality(allowed_types)<=1024 AND array_position(allowed_types,NULL) IS NULL
		 THEN ARRAY(SELECT CASE WHEN octet_length(v)<=1024 THEN v ELSE '' END FROM unnest(allowed_types)v) ELSE ARRAY[]::text[] END,
		CASE WHEN cardinality(excluded_fields)<=1024 AND array_position(excluded_fields,NULL) IS NULL
		 THEN ARRAY(SELECT CASE WHEN octet_length(v)<=1024 THEN v ELSE '' END FROM unnest(excluded_fields)v) ELSE ARRAY[]::text[] END,
		CASE WHEN octet_length(schema_version)<=1024 THEN schema_version ELSE '' END,created_at,
		(octet_length(name)>65536 OR octet_length(coalesce(description,''))>65536 OR octet_length(schema_version)>1024 OR
		 cardinality(allowed_types)>1024 OR cardinality(excluded_fields)>1024 OR
		 array_position(allowed_types,NULL) IS NOT NULL OR array_position(excluded_fields,NULL) IS NOT NULL OR
		 CASE WHEN cardinality(allowed_types)<=1024 THEN EXISTS(SELECT 1 FROM unnest(allowed_types)v WHERE octet_length(v)>1024) ELSE true END OR
		 CASE WHEN cardinality(excluded_fields)<=1024 THEN EXISTS(SELECT 1 FROM unnest(excluded_fields)v WHERE octet_length(v)>1024) ELSE true END)
		FROM redaction_profiles WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&p.Name, &p.Description, &p.AllowedTypes, &p.ExcludedFields, &p.SchemaVersion, &p.CreatedAt, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, app.ErrNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("read customer-package redaction policy: %w", err)
	}
	if oversized {
		return empty, app.ErrConflict
	}
	return p, nil
}
