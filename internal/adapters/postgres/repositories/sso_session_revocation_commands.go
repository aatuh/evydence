package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var _ identityapp.SSOSessionRevocationReader = identity{}

func (r identity) ReadSSOSessionForRevocation(ctx context.Context, tenant, id string) (identitydomain.SSOSession, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(id, 1024) {
		return identitydomain.SSOSession{}, app.ErrValidation
	}
	// Ownership and immutable metadata stay locked through audit/replay commit.
	// A revocation need not load a credential hash or any user/provider inventory,
	// nor require an active provider/user or an unexpired session.
	v := identitydomain.SSOSession{ID: id, TenantID: tenant}
	var groups []byte
	var revoked sql.NullTime
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT
	CASE WHEN octet_length(user_id)<=1024 THEN user_id ELSE '' END,
	CASE WHEN octet_length(provider_id)<=1024 THEN provider_id ELSE '' END,
	CASE WHEN octet_length(prefix)<=1024 THEN prefix ELSE '' END,
	CASE WHEN coalesce(octet_length(groups::text),0)<=131072 THEN coalesce(groups::text,'null') ELSE 'null' END,
	expires_at,revoked_at,
	CASE WHEN octet_length(schema_version)<=1024 THEN schema_version ELSE '' END,created_at,
	octet_length(user_id)>1024 OR octet_length(provider_id)>1024 OR octet_length(prefix)>1024 OR coalesce(octet_length(groups::text),0)>131072 OR octet_length(schema_version)>1024
	FROM sso_sessions WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&v.UserID, &v.ProviderID, &v.Prefix, &groups, &v.ExpiresAt, &revoked, &v.SchemaVersion, &v.CreatedAt, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitydomain.SSOSession{}, app.ErrNotFound
	}
	if err != nil {
		return identitydomain.SSOSession{}, writeError("read session revocation metadata", err)
	}
	var values []*string
	if oversized || json.Unmarshal(groups, &values) != nil {
		return identitydomain.SSOSession{}, app.ErrConflict
	}
	for _, value := range values {
		if value == nil {
			return identitydomain.SSOSession{}, app.ErrConflict
		}
		v.Groups = append(v.Groups, *value)
	}
	v.ExpiresAt = v.ExpiresAt.UTC()
	v.CreatedAt = v.CreatedAt.UTC()
	if revoked.Valid {
		now := revoked.Time.UTC()
		v.RevokedAt = &now
	}
	return v, nil
}
func (r identity) RevokeSSOSessionMetadata(ctx context.Context, previous identitydomain.SSOSession, now time.Time) error {
	if ctx == nil || r.tx == nil || previous.Hash != "" || previous.RevokedAt != nil || now.IsZero() || !validMembershipQueryText(previous.ID, 1024) || !validMembershipQueryText(previous.TenantID, 1024) || !validMembershipQueryText(previous.UserID, 1024) || !validMembershipQueryText(previous.ProviderID, 1024) {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `UPDATE sso_sessions SET revoked_at=$5 WHERE tenant_id=$1 AND id=$2 AND user_id=$3 AND provider_id=$4 AND revoked_at IS NULL`, previous.TenantID, previous.ID, previous.UserID, previous.ProviderID, now)
	if err != nil {
		return writeError("revoke session metadata", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}
