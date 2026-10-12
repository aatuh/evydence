package repositories

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

var _ identityapp.RoleBindingWriteReader = identity{}

func (r identity) LockRoleBindingWrites(ctx context.Context, tenant string) error {
	return r.LockAPIKeyCreation(ctx, tenant)
}
func (r identity) ValidateSubject(ctx context.Context, tenant, kind, id string) error {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(id, 1024) {
		return app.ErrValidation
	}
	switch kind {
	case "user":
		// Lock the user and its optional organization by identity only; no email,
		// display name, provider material or session credentials are selected.
		var org sql.NullString
		var large bool
		err := r.tx.QueryRow(ctx, `SELECT left(organization_id,1025),coalesce(octet_length(organization_id),0)>1024 FROM human_users WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&org, &large)
		if err := roleTargetReadError(err, large); err != nil {
			return err
		}
		if org.Valid && org.String != "" {
			_, err := r.ReadMembershipOrganization(ctx, tenant, org.String)
			return err
		}
		return nil
	case "collector":
		return requireRow(ctx, r.tx, `SELECT 1 FROM collectors c JOIN api_keys k ON k.id=c.api_key_id AND k.tenant_id=c.tenant_id WHERE c.tenant_id=$1 AND c.id=$2 FOR SHARE OF c,k`, tenant, id)
	default:
		return app.ErrValidation
	}
}
func (r identity) ValidateResource(ctx context.Context, tenant, kind, id string) error {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) {
		return app.ErrValidation
	}
	if id != "" && !validMembershipQueryText(id, 1024) {
		return app.ErrValidation
	}
	switch kind {
	case "":
		if id != "" {
			return app.ErrValidation
		}
		return nil
	case "tenant":
		if id != "" && id != tenant {
			return app.ErrNotFound
		}
		return requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant)
	case "product":
		if id == "" {
			return app.ErrNotFound
		}
		return requireRow(ctx, r.tx, `SELECT 1 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id)
	case "project":
		if id == "" {
			return app.ErrNotFound
		}
		return requireRow(ctx, r.tx, `SELECT 1 FROM projects p JOIN products product ON product.id=p.product_id AND product.tenant_id=p.tenant_id WHERE p.tenant_id=$1 AND p.id=$2 FOR SHARE OF p,product`, tenant, id)
	case "release":
		return r.lockRoleRelease(ctx, tenant, id, "")
	case "customer_security_package":
		if id == "" {
			return app.ErrNotFound
		}
		var product, release string
		var large bool
		err := r.tx.QueryRow(ctx, `SELECT left(p.product_id,1025),left(coalesce(p.release_id,''),1025),octet_length(p.product_id)>1024 OR coalesce(octet_length(p.release_id),0)>1024
		FROM customer_security_packages p JOIN products product ON product.id=p.product_id AND product.tenant_id=p.tenant_id
		WHERE p.tenant_id=$1 AND p.id=$2 FOR SHARE OF p,product`, tenant, id).Scan(&product, &release, &large)
		if err := roleTargetReadError(err, large); err != nil {
			return err
		}
		if release != "" {
			return r.lockRoleRelease(ctx, tenant, release, product)
		}
		return nil
	case "evidence_bundle":
		if id == "" {
			return app.ErrNotFound
		}
		var release string
		var large bool
		err := r.tx.QueryRow(ctx, `SELECT left(coalesce(release_id,''),1025),coalesce(octet_length(release_id),0)>1024 FROM evidence_bundles WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&release, &large)
		if err := roleTargetReadError(err, large); err != nil {
			return err
		}
		if release != "" {
			return r.lockRoleRelease(ctx, tenant, release, "")
		}
		return nil
	default:
		return app.ErrValidation
	}
}
func (r identity) lockRoleRelease(ctx context.Context, tenant, id, product string) error {
	if id == "" {
		return app.ErrNotFound
	}
	if !validMembershipQueryText(id, 1024) || product != "" && !validMembershipQueryText(product, 1024) {
		return app.ErrConflict
	}
	return requireRow(ctx, r.tx, `SELECT 1 FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.id=$2 AND ($3='' OR r.product_id=$3) FOR SHARE OF r,p`, tenant, id, product)
}
func roleTargetReadError(err error, large bool) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return writeError("read role target identity", err)
	}
	if large {
		return app.ErrConflict
	}
	return nil
}
