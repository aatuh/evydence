package repositories

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// LockReleaseBundleParent prevents reparenting across the write transaction.
// Both the release and its parent product must belong to the requested tenant.
func (r packages) LockReleaseBundleParent(ctx context.Context, tenantID, releaseID string) (string, error) {
	if ctx == nil || r.tx == nil || !validRetentionCoordinate(tenantID) {
		return "", app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	id, normalizeErr := packageapp.NormalizeReleaseBundleID(releaseID)
	if normalizeErr != nil || id != releaseID {
		return "", app.ErrValidation
	}
	var productID string
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT left(r.product_id,1025),octet_length(r.product_id)>1024
		FROM releases r JOIN products p ON p.id=r.product_id AND p.tenant_id=r.tenant_id
		WHERE r.id=$1 AND r.tenant_id=$2 FOR SHARE OF r,p`, releaseID, tenantID).Scan(&productID, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", app.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("lock bundle release scope: %w", err)
	}
	if oversized || productID == "" || strings.TrimSpace(productID) != productID {
		return "", app.ErrConflict
	}
	return productID, nil
}

// ValidatePackageSignature share-locks public lifecycle fields and verifies
// the exact hash signature before insertion. Revocation/rotation cannot race
// commit after this check; private bytes are never selected here.
func (r signatures) ValidatePackageSignature(ctx context.Context, signature domain.Signature, payloadHash string) error {
	var algorithm, provider, status, public string
	var from time.Time
	var until, revoked, compromised *time.Time
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT left(algorithm,65),left(provider,65),left(status,65),left(public_key,129),
		valid_from,valid_until,revoked_at,compromised_at,
		(octet_length(algorithm)>64 OR octet_length(provider)>64 OR octet_length(status)>64 OR octet_length(public_key)>128)
		FROM signing_keys WHERE tenant_id=$1 AND id=$2 FOR SHARE`, signature.TenantID, signature.KeyID).Scan(&algorithm, &provider, &status, &public, &from, &until, &revoked, &compromised, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock bundle signing key: %w", err)
	}
	if oversized || signature.Algorithm != "Ed25519" || algorithm != signature.Algorithm || provider != "local_ed25519" || status != "active" || from.After(signature.CreatedAt) || until != nil && !signature.CreatedAt.Before(*until) || revoked != nil || compromised != nil {
		return app.ErrConflict
	}
	publicBytes, err := base64.RawStdEncoding.Strict().DecodeString(public)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return app.ErrConflict
	}
	if len(signature.Value) > 128 {
		return app.ErrConflict
	}
	value, err := base64.RawStdEncoding.Strict().DecodeString(signature.Value)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicBytes), []byte(payloadHash), value) {
		return app.ErrConflict
	}
	return nil
}
