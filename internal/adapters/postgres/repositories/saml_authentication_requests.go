package repositories

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func validSAMLRequestRecord(v identitydomain.SAMLAuthenticationRequest) bool {
	_, format, err := identityapp.NormalizeSAMLBindingParameters(v.Recipient, v.NameIDFormat)
	return err == nil && format == v.NameIDFormat && identitydomain.ValidSAMLID(v.ID) && validMembershipQueryText(v.TenantID, 1024) && validMembershipQueryText(v.ProviderID, 1024) && validMembershipQueryText(v.Issuer, 4096) && validMembershipQueryText(v.Audience, 4096) && len(v.TrustFingerprint) == 71 && strings.HasPrefix(v.TrustFingerprint, "sha256:") && oidcRequestHash(v.TrustFingerprint[7:]) && oidcRequestHash(v.StateHash)
}

func samlRequestMatchesBinding(v identitydomain.SAMLAuthenticationRequest, b identitydomain.SAMLProviderBinding) bool {
	fp, err := identityapp.SAMLProviderTrustFingerprint(b)
	return err == nil && identityapp.ValidSAMLProviderBinding(b) && fp == v.TrustFingerprint && v.Issuer == b.Provider.Issuer && v.Audience == b.Provider.ClientID && v.Recipient == b.Recipient && v.NameIDFormat == b.NameIDFormat
}

func (r identity) InsertSAMLAuthenticationRequest(ctx context.Context, v identitydomain.SAMLAuthenticationRequest, at time.Time) error {
	if ctx == nil || r.tx == nil || !validSAMLRequestRecord(v) || !v.PendingAt(at) {
		return app.ErrValidation
	}
	b, err := r.ReadOwnedSAMLProviderBinding(ctx, v.TenantID, v.ProviderID)
	if err != nil {
		return err
	}
	if !samlRequestMatchesBinding(v, b) {
		return app.ErrConflict
	}
	// Keep assertion markers through their signed expiry, including a proof
	// whose expiry outlives the five-minute login request. Never erase history.
	if _, err := r.tx.Exec(ctx, `DELETE FROM saml_assertion_consumptions WHERE (tenant_id,provider_id,assertion_hash) IN (SELECT tenant_id,provider_id,assertion_hash FROM saml_assertion_consumptions WHERE tenant_id=$1 AND provider_id=$2 AND expires_at<=$3 ORDER BY expires_at,assertion_hash LIMIT 64)`, v.TenantID, v.ProviderID, at); err != nil {
		return writeError("prune expired SAML assertion state", err)
	}
	if _, err := r.tx.Exec(ctx, `DELETE FROM saml_authentication_requests WHERE id IN (SELECT q.id FROM saml_authentication_requests q WHERE q.tenant_id=$1 AND q.provider_id=$2 AND q.expires_at<=$3 AND NOT EXISTS(SELECT 1 FROM saml_assertion_consumptions m WHERE m.tenant_id=q.tenant_id AND m.provider_id=q.provider_id AND m.request_id=q.id) ORDER BY q.expires_at,q.id LIMIT 64)`, v.TenantID, v.ProviderID, at); err != nil {
		return writeError("prune expired SAML login state", err)
	}
	var count int
	if err := r.tx.QueryRow(ctx, `SELECT count(*) FROM(SELECT id FROM saml_authentication_requests WHERE tenant_id=$1 AND provider_id=$2 LIMIT 65) bounded`, v.TenantID, v.ProviderID).Scan(&count); err != nil {
		return writeError("check SAML request capacity", err)
	}
	if count >= identitydomain.MaximumSAMLAuthenticationRequestsPerProvider {
		return app.ErrRateLimited
	}
	_, err = r.tx.Exec(ctx, `INSERT INTO saml_authentication_requests(id,tenant_id,provider_id,delivery,issuer,audience,recipient,name_id_format,trust_fingerprint,state_hash,created_at,expires_at,schema_version)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, v.ID, v.TenantID, v.ProviderID, v.Delivery, v.Issuer, v.Audience, v.Recipient, v.NameIDFormat, v.TrustFingerprint, v.StateHash, v.CreatedAt, v.ExpiresAt, v.SchemaVersion)
	return writeError("insert SAML authentication request", err)
}

func (r identity) ReadSAMLAuthenticationRequest(ctx context.Context, tenant, provider, id string) (identitydomain.SAMLAuthenticationRequest, error) {
	return r.readSAMLAuthenticationRequest(ctx, tenant, provider, id, false)
}
func (r identity) readSAMLAuthenticationRequest(ctx context.Context, tenant, provider, id string, lock bool) (identitydomain.SAMLAuthenticationRequest, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(provider, 1024) || !identitydomain.ValidSAMLID(id) {
		return identitydomain.SAMLAuthenticationRequest{}, app.ErrValidation
	}
	clause := ""
	if lock {
		clause = " FOR UPDATE"
	}
	var v identitydomain.SAMLAuthenticationRequest
	var consumed sql.NullTime
	err := r.tx.QueryRow(ctx, `SELECT id,tenant_id,provider_id,delivery,issuer,audience,recipient,name_id_format,trust_fingerprint,state_hash,created_at,expires_at,consumed_at,schema_version FROM saml_authentication_requests WHERE tenant_id=$1 AND provider_id=$2 AND id=$3`+clause, tenant, provider, id).Scan(&v.ID, &v.TenantID, &v.ProviderID, &v.Delivery, &v.Issuer, &v.Audience, &v.Recipient, &v.NameIDFormat, &v.TrustFingerprint, &v.StateHash, &v.CreatedAt, &v.ExpiresAt, &consumed, &v.SchemaVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitydomain.SAMLAuthenticationRequest{}, app.ErrNotFound
	}
	if err != nil {
		return identitydomain.SAMLAuthenticationRequest{}, writeError("read owned SAML authentication request", err)
	}
	v.CreatedAt, v.ExpiresAt = v.CreatedAt.UTC(), v.ExpiresAt.UTC()
	if consumed.Valid {
		at := consumed.Time.UTC()
		v.ConsumedAt = &at
	}
	if !validSAMLRequestRecord(v) {
		return identitydomain.SAMLAuthenticationRequest{}, app.ErrUnauthorized
	}
	return v, nil
}

func (r identity) ConsumeSAMLAuthenticationRequest(ctx context.Context, expected identitydomain.SAMLAuthenticationRequest, proof identitydomain.SAMLAssertionUse, clock application.Clock) (time.Time, error) {
	if ctx == nil || r.tx == nil || clock == nil || !validSAMLRequestRecord(expected) {
		return time.Time{}, app.ErrValidation
	}
	b, err := r.ReadOwnedSAMLProviderBinding(ctx, expected.TenantID, expected.ProviderID)
	if err != nil {
		return time.Time{}, err
	}
	if !samlRequestMatchesBinding(expected, b) {
		return time.Time{}, app.ErrUnauthorized
	}
	current, err := r.readSAMLAuthenticationRequest(ctx, expected.TenantID, expected.ProviderID, expected.ID, true)
	if errors.Is(err, app.ErrNotFound) {
		return time.Time{}, app.ErrUnauthorized
	}
	if err != nil {
		return time.Time{}, err
	}
	if current.Delivery != expected.Delivery || current.Issuer != expected.Issuer || current.Audience != expected.Audience || current.Recipient != expected.Recipient || current.NameIDFormat != expected.NameIDFormat || current.TrustFingerprint != expected.TrustFingerprint || current.StateHash != expected.StateHash || current.SchemaVersion != expected.SchemaVersion || !current.CreatedAt.Equal(expected.CreatedAt) || !current.ExpiresAt.Equal(expected.ExpiresAt) {
		return time.Time{}, app.ErrUnauthorized
	}
	at := clock.Now().UTC().Truncate(time.Microsecond)
	if !current.PendingAt(at) || !proof.ValidAt(at) || proof.IssuedAt.Before(current.CreatedAt.Add(-time.Minute)) {
		return time.Time{}, app.ErrUnauthorized
	}
	var inserted string
	err = r.tx.QueryRow(ctx, `INSERT INTO saml_assertion_consumptions(tenant_id,provider_id,assertion_hash,request_id,consumed_at,expires_at,schema_version)VALUES($1,$2,$3,$4,$5,$6,'saml-assertion-consumption.v1.0.0')ON CONFLICT DO NOTHING RETURNING request_id`, current.TenantID, current.ProviderID, proof.AssertionHash, current.ID, at, proof.ExpiresAt).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, app.ErrUnauthorized
	}
	if err != nil {
		return time.Time{}, writeError("record scoped SAML assertion consumption", err)
	}
	var consumed time.Time
	err = r.tx.QueryRow(ctx, `UPDATE saml_authentication_requests SET consumed_at=$4 WHERE tenant_id=$1 AND provider_id=$2 AND id=$3 AND consumed_at IS NULL RETURNING consumed_at`, current.TenantID, current.ProviderID, current.ID, at).Scan(&consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, app.ErrUnauthorized
	}
	if err != nil {
		return time.Time{}, writeError("consume SAML authentication request", err)
	}
	return consumed.UTC(), ctx.Err()
}
