package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var _ identityapp.SSOProviderWriteReader = identity{}

func (r identity) LockSSOProviderCreation(ctx context.Context, tenant string) error {
	return r.LockAPIKeyCreation(ctx, tenant)
}

func (r identity) ReadOwnedSSOProvider(ctx context.Context, tenant, id string) (identitydomain.SSOProvider, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(id, 1024) {
		return identitydomain.SSOProvider{}, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	// Preserve complete metadata or reject excess historical data. The CASEs
	// bound bytes transferred, never truncate a returned provider. JSONB text
	// allows bounded formatting overhead above the compact input limits.
	p := identitydomain.SSOProvider{ID: id, TenantID: tenant}
	var roleMapping, jwks, certificates []byte
	var updated sql.NullTime
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT
	CASE WHEN octet_length(name)<=65536 THEN name ELSE '' END,
	CASE WHEN octet_length(type)<=128 THEN type ELSE '' END,
	CASE WHEN octet_length(issuer)<=65536 THEN issuer ELSE '' END,
	CASE WHEN octet_length(client_id)<=65536 THEN client_id ELSE '' END,
	CASE WHEN coalesce(octet_length(groups_claim),0)<=65536 THEN coalesce(groups_claim,'') ELSE '' END,
	CASE WHEN coalesce(octet_length(role_mapping::text),0)<=131072 THEN coalesce(role_mapping::text,'null') ELSE 'null' END,
	CASE WHEN coalesce(octet_length(jwks::text),0)<=131072 THEN coalesce(jwks::text,'null') ELSE 'null' END,
	CASE WHEN coalesce(octet_length(saml_signing_certificates::text),0)<=131072 THEN coalesce(saml_signing_certificates::text,'null') ELSE 'null' END,
	trust_material_updated_at,
	CASE WHEN octet_length(status)<=128 THEN status ELSE '' END,
	CASE WHEN octet_length(schema_version)<=1024 THEN schema_version ELSE '' END,created_at,
	octet_length(name)>65536 OR octet_length(type)>128 OR octet_length(issuer)>65536 OR octet_length(client_id)>65536 OR coalesce(octet_length(groups_claim),0)>65536 OR coalesce(octet_length(role_mapping::text),0)>131072 OR coalesce(octet_length(jwks::text),0)>131072 OR coalesce(octet_length(saml_signing_certificates::text),0)>131072 OR octet_length(status)>128 OR octet_length(schema_version)>1024
	FROM sso_providers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&p.Name, &p.Type, &p.Issuer, &p.ClientID, &p.GroupsClaim, &roleMapping, &jwks, &certificates, &updated, &p.Status, &p.SchemaVersion, &p.CreatedAt, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitydomain.SSOProvider{}, app.ErrNotFound
	}
	if err != nil {
		return identitydomain.SSOProvider{}, writeError("read owned SSO provider", err)
	}
	if oversized || json.Unmarshal(roleMapping, &p.RoleMapping) != nil || json.Unmarshal(jwks, &p.JWKS) != nil || json.Unmarshal(certificates, &p.SAMLSigningCertificates) != nil {
		return identitydomain.SSOProvider{}, app.ErrConflict
	}
	p.CreatedAt = p.CreatedAt.UTC()
	if updated.Valid {
		v := updated.Time.UTC()
		p.TrustMaterialUpdatedAt = &v
	}
	return p, nil
}
