package repositories

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func (r identity) lockOIDCRequestProvider(ctx context.Context, tenant, provider string) (identitydomain.SSOProvider, error) {
	if ctx == nil || r.tx == nil || tenant == "" || provider == "" || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(provider, 1024) {
		return identitydomain.SSOProvider{}, app.ErrValidation
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return identitydomain.SSOProvider{}, writeError("lock OIDC request mutation", err)
	}
	p, err := r.ReadOwnedSSOProvider(ctx, tenant, provider)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	if p.Type != "oidc" || p.Status != "active" || p.Issuer == "" || p.ClientID == "" || len(p.JWKS) == 0 {
		return identitydomain.SSOProvider{}, app.ErrUnauthorized
	}
	return p, nil
}

func (r identity) ValidateOIDCProvider(ctx context.Context, expected identitydomain.SSOProvider) error {
	current, err := r.lockOIDCRequestProvider(ctx, expected.TenantID, expected.ID)
	if err != nil {
		return err
	}
	want, err := identityapp.OIDCProviderTrustFingerprint(expected)
	if err != nil {
		return app.ErrValidation
	}
	got, err := identityapp.OIDCProviderTrustFingerprint(current)
	if err != nil {
		return app.ErrValidation
	}
	if want != got {
		return app.ErrConflict
	}
	return nil
}

func oidcRequestHash(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
func validOIDCRequestRecord(v identitydomain.OIDCAuthenticationRequest) bool {
	return v.ID != "" && v.TenantID != "" && v.ProviderID != "" && validMembershipQueryText(v.ID, 1024) && validMembershipQueryText(v.TenantID, 1024) && validMembershipQueryText(v.ProviderID, 1024) &&
		len(v.TrustFingerprint) == 71 && strings.HasPrefix(v.TrustFingerprint, "sha256:") && oidcRequestHash(v.TrustFingerprint[7:]) && oidcRequestHash(v.StateHash) && oidcRequestHash(v.NonceHash) && v.StateHash != v.NonceHash
}

func (r identity) InsertOIDCAuthenticationRequest(ctx context.Context, v identitydomain.OIDCAuthenticationRequest, at time.Time) error {
	if ctx == nil || r.tx == nil || !validOIDCRequestRecord(v) || !v.PendingAt(at) {
		return app.ErrValidation
	}
	provider, err := r.lockOIDCRequestProvider(ctx, v.TenantID, v.ProviderID)
	if err != nil {
		return err
	}
	fingerprint, err := identityapp.OIDCProviderTrustFingerprint(provider)
	if err != nil || fingerprint != v.TrustFingerprint {
		return app.ErrConflict
	}
	// Only operational state expires; audit/evidence/session history remains.
	if _, err := r.tx.Exec(ctx, `DELETE FROM oidc_authentication_requests WHERE id IN (
		SELECT id FROM oidc_authentication_requests WHERE tenant_id=$1 AND provider_id=$2 AND expires_at<=$3 ORDER BY expires_at,id LIMIT 64)`, v.TenantID, v.ProviderID, at); err != nil {
		return writeError("prune expired OIDC request state", err)
	}
	var count int
	if err := r.tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT id FROM oidc_authentication_requests WHERE tenant_id=$1 AND provider_id=$2 LIMIT 65) bounded`, v.TenantID, v.ProviderID).Scan(&count); err != nil {
		return writeError("check OIDC request capacity", err)
	}
	if count >= identitydomain.MaximumOIDCAuthenticationRequestsPerProvider {
		return app.ErrRateLimited
	}
	_, err = r.tx.Exec(ctx, `INSERT INTO oidc_authentication_requests(id,tenant_id,provider_id,delivery,trust_fingerprint,state_hash,nonce_hash,created_at,expires_at,schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, v.ID, v.TenantID, v.ProviderID, v.Delivery, v.TrustFingerprint, v.StateHash, v.NonceHash, v.CreatedAt, v.ExpiresAt, v.SchemaVersion)
	return writeError("insert OIDC authentication request", err)
}

func (r identity) ReadOIDCAuthenticationRequest(ctx context.Context, tenant, provider, id string) (identitydomain.OIDCAuthenticationRequest, error) {
	return r.readOIDCAuthenticationRequest(ctx, tenant, provider, id, false)
}
func (r identity) readOIDCAuthenticationRequest(ctx context.Context, tenant, provider, id string, lock bool) (identitydomain.OIDCAuthenticationRequest, error) {
	if ctx == nil || r.tx == nil || tenant == "" || provider == "" || id == "" || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(provider, 1024) || !validMembershipQueryText(id, 1024) {
		return identitydomain.OIDCAuthenticationRequest{}, app.ErrValidation
	}
	clause := ""
	if lock {
		clause = " FOR UPDATE"
	}
	var v identitydomain.OIDCAuthenticationRequest
	var consumed sql.NullTime
	err := r.tx.QueryRow(ctx, `SELECT id,tenant_id,provider_id,delivery,trust_fingerprint,state_hash,nonce_hash,created_at,expires_at,consumed_at,schema_version FROM oidc_authentication_requests WHERE tenant_id=$1 AND provider_id=$2 AND id=$3`+clause, tenant, provider, id).Scan(&v.ID, &v.TenantID, &v.ProviderID, &v.Delivery, &v.TrustFingerprint, &v.StateHash, &v.NonceHash, &v.CreatedAt, &v.ExpiresAt, &consumed, &v.SchemaVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitydomain.OIDCAuthenticationRequest{}, app.ErrNotFound
	}
	if err != nil {
		return identitydomain.OIDCAuthenticationRequest{}, writeError("read scoped OIDC authentication request", err)
	}
	if consumed.Valid {
		at := consumed.Time.UTC()
		v.ConsumedAt = &at
	}
	if !validOIDCRequestRecord(v) {
		return identitydomain.OIDCAuthenticationRequest{}, app.ErrUnauthorized
	}
	return v, nil
}

func (r identity) ConsumeOIDCAuthenticationRequest(ctx context.Context, expected identitydomain.OIDCAuthenticationRequest, clock application.Clock) (time.Time, error) {
	if clock == nil || !validOIDCRequestRecord(expected) {
		return time.Time{}, app.ErrValidation
	}
	provider, err := r.lockOIDCRequestProvider(ctx, expected.TenantID, expected.ProviderID)
	if err != nil {
		return time.Time{}, err
	}
	fingerprint, err := identityapp.OIDCProviderTrustFingerprint(provider)
	if err != nil || fingerprint != expected.TrustFingerprint {
		return time.Time{}, app.ErrUnauthorized
	}
	current, err := r.readOIDCAuthenticationRequest(ctx, expected.TenantID, expected.ProviderID, expected.ID, true)
	if errors.Is(err, app.ErrNotFound) {
		return time.Time{}, app.ErrUnauthorized
	}
	if err != nil {
		return time.Time{}, err
	}
	if current.StateHash != expected.StateHash || current.NonceHash != expected.NonceHash || current.TrustFingerprint != expected.TrustFingerprint || current.Delivery != expected.Delivery || current.SchemaVersion != expected.SchemaVersion || !current.CreatedAt.Equal(expected.CreatedAt) || !current.ExpiresAt.Equal(expected.ExpiresAt) {
		return time.Time{}, app.ErrUnauthorized
	}
	// Clock is sampled only after the mutation/provider/request locks.
	at := clock.Now().UTC().Truncate(time.Microsecond)
	if !current.PendingAt(at) {
		return time.Time{}, app.ErrUnauthorized
	}
	var consumed time.Time
	err = r.tx.QueryRow(ctx, `UPDATE oidc_authentication_requests SET consumed_at=$4 WHERE tenant_id=$1 AND provider_id=$2 AND id=$3 AND consumed_at IS NULL RETURNING consumed_at`, current.TenantID, current.ProviderID, current.ID, at).Scan(&consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, app.ErrUnauthorized
	}
	if err != nil {
		return time.Time{}, writeError("consume OIDC authentication request", err)
	}
	return consumed.UTC(), ctx.Err()
}
