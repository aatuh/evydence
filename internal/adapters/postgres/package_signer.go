package postgres

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/application"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// SignPackage preserves the existing local Ed25519 package-signature format.
// It reads one current tenant key, bounds every field and clears the private
// bytes. It neither hydrates Ledger nor invokes a provider signing workflow.
// The command's transaction must revalidate/share-lock this key before commit.
func (s *Store) SignPackage(ctx context.Context, request packageapp.PackageSigningRequest) (packageapp.PackageSignature, error) {
	var empty packageapp.PackageSignature
	if s == nil || s.pool == nil || ctx == nil || request.TenantID == "" || request.SubjectID == "" || request.SubjectType == "" || request.PayloadHash == "" || request.CreatedAt.IsZero() {
		return empty, packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	var id, algorithm, provider, public string
	var private []byte
	var from time.Time
	var until, revoked, compromised *time.Time
	var oversized bool
	err := s.pool.QueryRow(ctx, `SELECT left(id,1025),left(algorithm,65),left(provider,65),left(public_key,129),
		CASE WHEN octet_length(encrypted_private_key)=64 THEN encrypted_private_key ELSE NULL END,
		valid_from,valid_until,revoked_at,compromised_at,
		(octet_length(id)>1024 OR octet_length(algorithm)>64 OR octet_length(provider)>64 OR octet_length(public_key)>128)
		FROM signing_keys WHERE tenant_id=$1 AND status='active' ORDER BY version DESC,id ASC LIMIT 1`, request.TenantID).Scan(&id, &algorithm, &provider, &public, &private, &from, &until, &revoked, &compromised, &oversized)
	defer clear(private)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, packageapp.ErrConflict
	}
	if err != nil {
		return empty, fmt.Errorf("read package signing key: %w", err)
	}
	if oversized || algorithm != "Ed25519" || provider != "local_ed25519" || len(private) != ed25519.PrivateKeySize || from.After(request.CreatedAt) || until != nil && !request.CreatedAt.Before(*until) || revoked != nil || compromised != nil {
		return empty, packageapp.ErrConflict
	}
	publicBytes, err := base64.RawStdEncoding.Strict().DecodeString(public)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize || !ed25519.PublicKey(private[ed25519.SeedSize:]).Equal(ed25519.PublicKey(publicBytes)) {
		return empty, packageapp.ErrConflict
	}
	if strings.TrimSpace(id) == "" {
		return empty, packageapp.ErrConflict
	}
	value := ed25519.Sign(ed25519.PrivateKey(private), []byte(request.PayloadHash))
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return packageapp.PackageSignature{ID: application.NewID("sig"), TenantID: request.TenantID, SubjectType: request.SubjectType, SubjectID: request.SubjectID, KeyID: id, Algorithm: algorithm, Value: base64.RawStdEncoding.EncodeToString(value), CreatedAt: request.CreatedAt}, nil
}
