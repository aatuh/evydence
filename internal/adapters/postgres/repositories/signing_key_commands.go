package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Public lifecycle fields only: private key material is never selected.
const signingAdminColumns = `left(id,1025),left(tenant_id,1025),left(kid,1025),version,left(provider,65),left(algorithm,65),left(status,65),left(public_key,16385),left(public_key_fingerprint,1025),valid_from,valid_until,created_at,revoked_at,left(revocation_reason,4097),left(revocation_semantics,65),left(historical_validity_policy,65),compromised_at,
 (octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(kid)>1024 OR octet_length(provider)>64 OR octet_length(algorithm)>64 OR octet_length(status)>64 OR octet_length(public_key)>16384 OR octet_length(public_key_fingerprint)>1024 OR octet_length(revocation_reason)>4096 OR octet_length(revocation_semantics)>64 OR octet_length(historical_validity_policy)>64)`

func scanSigningAdminKey(row interface{ Scan(...any) error }) (verificationdomain.SigningKey, error) {
	var key verificationdomain.SigningKey
	var status string
	var oversized bool
	err := row.Scan(&key.ID, &key.TenantID, &key.KID, &key.Version, &key.Provider, &key.Algorithm, &status, &key.PublicKey, &key.PublicKeyFingerprint, &key.ValidFrom, &key.ValidUntil, &key.CreatedAt, &key.RevokedAt, &key.RevocationReason, &key.RevocationSemantics, &key.HistoricalValidityPolicy, &key.CompromisedAt, &oversized)
	if err != nil {
		return key, err
	}
	key.Status, err = verificationdomain.ParseSigningKeyStatus(status)
	if err != nil || oversized || key.ID == "" || key.TenantID == "" || key.KID == "" || key.Version < 1 || key.Version > 2147483647 || key.Algorithm == "" || key.PublicKey == "" || key.CreatedAt.IsZero() || key.ValidFrom.IsZero() {
		return verificationdomain.SigningKey{}, app.ErrConflict
	}
	return key, nil
}

// The tenant row is the per-tenant lifecycle lock, including empty key sets.
// Lock order is tenant then signing keys ordered by ID for both commands.
func (r signatures) lockSigningKeyTenant(ctx context.Context, tenantID string) error {
	return requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR UPDATE`, tenantID)
}

func (r signatures) ListLocalSigningKeysForUpdate(ctx context.Context, tenantID string) ([]verificationdomain.SigningKey, error) {
	if err := r.lockSigningKeyTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	rows, err := r.tx.Query(ctx, `SELECT `+signingAdminColumns+` FROM signing_keys WHERE tenant_id=$1 AND coalesce(nullif(provider,''),'local_ed25519')='local_ed25519' ORDER BY id LIMIT $2 FOR UPDATE`, tenantID, verificationapp.MaxSigningRotationKeys+1)
	if err != nil {
		return nil, fmt.Errorf("lock local signing keys: %w", err)
	}
	defer rows.Close()
	keys := make([]verificationdomain.SigningKey, 0)
	bytes := 0
	for rows.Next() {
		key, err := scanSigningAdminKey(rows)
		if err != nil {
			return nil, err
		}
		bytes += len(key.ID) + len(key.TenantID) + len(key.KID) + len(key.Provider) + len(key.Algorithm) + len(key.Status.String()) + len(key.PublicKey) + len(key.PublicKeyFingerprint) + len(key.RevocationReason) + len(key.RevocationSemantics) + len(key.HistoricalValidityPolicy)
		if len(keys) == verificationapp.MaxSigningRotationKeys || bytes > 8<<20 {
			return nil, app.ErrConflict
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate locked signing keys: %w", err)
	}
	return keys, nil
}

func (r signatures) GetSigningKeyForUpdate(ctx context.Context, tenantID, id string) (verificationdomain.SigningKey, error) {
	if err := r.lockSigningKeyTenant(ctx, tenantID); err != nil {
		return verificationdomain.SigningKey{}, err
	}
	key, err := scanSigningAdminKey(r.tx.QueryRow(ctx, `SELECT `+signingAdminColumns+` FROM signing_keys WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return verificationdomain.SigningKey{}, app.ErrNotFound
	}
	if err != nil {
		return verificationdomain.SigningKey{}, fmt.Errorf("lock signing key: %w", err)
	}
	return key, nil
}
