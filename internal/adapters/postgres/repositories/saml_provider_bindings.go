package repositories

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func (r identity) lockSAMLProvider(ctx context.Context, tenant, provider string) (identitydomain.SSOProvider, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(provider, 1024) {
		return identitydomain.SSOProvider{}, app.ErrValidation
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return identitydomain.SSOProvider{}, writeError("lock SAML provider mutation", err)
	}
	return r.ReadOwnedSSOProvider(ctx, tenant, provider)
}

func (r identity) SAMLProviderBindingByID(ctx context.Context, id string) (identitydomain.SAMLProviderBinding, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(id, 1024) {
		return identitydomain.SAMLProviderBinding{}, app.ErrValidation
	}
	var tenant string
	var oversized bool
	// Resolve the public coordinate without holding a provider lock before the
	// tenant mutation fence. Revalidate ownership in the locked scoped read.
	err := r.tx.QueryRow(ctx, `SELECT CASE WHEN octet_length(tenant_id)<=1024 THEN tenant_id ELSE '' END,octet_length(tenant_id)>1024 FROM sso_providers WHERE id=$1`, id).Scan(&tenant, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitydomain.SAMLProviderBinding{}, app.ErrNotFound
	}
	if err != nil {
		return identitydomain.SAMLProviderBinding{}, writeError("read public SAML provider coordinate", err)
	}
	if oversized || tenant == "" {
		return identitydomain.SAMLProviderBinding{}, app.ErrConflict
	}
	return r.ReadOwnedSAMLProviderBinding(ctx, tenant, id)
}

func (r identity) ReadOwnedSAMLProviderBinding(ctx context.Context, tenant, id string) (identitydomain.SAMLProviderBinding, error) {
	p, err := r.lockSAMLProvider(ctx, tenant, id)
	if err != nil {
		return identitydomain.SAMLProviderBinding{}, err
	}
	b := identitydomain.SAMLProviderBinding{TenantID: tenant, ProviderID: id, Provider: p}
	err = r.tx.QueryRow(ctx, `SELECT recipient,name_id_format,schema_version,updated_at FROM saml_provider_bindings WHERE tenant_id=$1 AND provider_id=$2 FOR UPDATE`, tenant, id).Scan(&b.Recipient, &b.NameIDFormat, &b.SchemaVersion, &b.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitydomain.SAMLProviderBinding{}, app.ErrNotFound
	}
	if err != nil {
		return identitydomain.SAMLProviderBinding{}, writeError("read owned SAML provider binding", err)
	}
	b.UpdatedAt = b.UpdatedAt.UTC()
	return b, nil
}

func (r identity) UpsertSAMLProviderBinding(ctx context.Context, b identitydomain.SAMLProviderBinding) error {
	if !identityapp.ValidSAMLProviderBinding(b) {
		return app.ErrValidation
	}
	p, err := r.lockSAMLProvider(ctx, b.TenantID, b.ProviderID)
	if err != nil {
		return err
	}
	expected, current := b, b
	current.Provider = p
	want, err := identityapp.SAMLProviderTrustFingerprint(expected)
	if err != nil {
		return app.ErrValidation
	}
	got, err := identityapp.SAMLProviderTrustFingerprint(current)
	if err != nil || got != want {
		return app.ErrConflict
	}
	result, err := r.tx.Exec(ctx, `INSERT INTO saml_provider_bindings(tenant_id,provider_id,recipient,name_id_format,schema_version,updated_at)VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,provider_id)DO UPDATE SET recipient=excluded.recipient,name_id_format=excluded.name_id_format,schema_version=excluded.schema_version,updated_at=excluded.updated_at WHERE saml_provider_bindings.updated_at<=excluded.updated_at`, b.TenantID, b.ProviderID, b.Recipient, b.NameIDFormat, b.SchemaVersion, b.UpdatedAt)
	if err != nil {
		return writeError("upsert SAML provider binding", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r identity) ValidateSAMLProviderBinding(ctx context.Context, expected identitydomain.SAMLProviderBinding) error {
	current, err := r.ReadOwnedSAMLProviderBinding(ctx, expected.TenantID, expected.ProviderID)
	if err != nil {
		return err
	}
	if !identityapp.ValidSAMLProviderBinding(current) {
		return app.ErrUnauthorized
	}
	want, err := identityapp.SAMLProviderTrustFingerprint(expected)
	if err != nil {
		return app.ErrValidation
	}
	got, err := identityapp.SAMLProviderTrustFingerprint(current)
	if err != nil || want != got {
		return app.ErrConflict
	}
	return nil
}
