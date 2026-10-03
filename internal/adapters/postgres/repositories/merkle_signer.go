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

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// SignMerkleRoot uses the caller's transaction and returns a prepared key only
// when no local key is active. The command inserts that key with its batch and
// audit. Existing private bytes never leave this adapter; prepared bytes are
// owned and cleared by the application command after synchronous insertion.
func (r signatures) SignMerkleRoot(ctx context.Context, request verificationapp.SigningRequest) (verificationapp.SigningResult, error) {
	var empty verificationapp.SigningResult
	if ctx == nil {
		return empty, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if request.TenantID == "" || request.SubjectType != "merkle_batch" || request.SubjectID == "" || len(request.Payload) == 0 || len(request.Payload) > 1024 || request.CreatedAt.IsZero() {
		return empty, app.ErrValidation
	}
	if err := r.lockSigningKeyTenant(ctx, request.TenantID); err != nil {
		return empty, err
	}
	var id, algorithm, public string
	var private []byte
	var from time.Time
	var until, revoked, compromised *time.Time
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(algorithm,65),left(public_key,129),CASE WHEN octet_length(encrypted_private_key)=64 THEN encrypted_private_key ELSE NULL END,valid_from,valid_until,revoked_at,compromised_at,(octet_length(id)>1024 OR octet_length(algorithm)>64 OR octet_length(public_key)>128) FROM signing_keys WHERE tenant_id=$1 AND status='active' AND coalesce(nullif(provider,''),'local_ed25519')='local_ed25519' ORDER BY version DESC,id ASC LIMIT 1 FOR SHARE`, request.TenantID).Scan(&id, &algorithm, &public, &private, &from, &until, &revoked, &compromised, &oversized)
	defer func() { clear(private) }()
	var prepared *verificationapp.PreparedSigningKey
	if errors.Is(err, pgx.ErrNoRows) {
		var version int64
		if err := r.tx.QueryRow(ctx, `SELECT coalesce(max(version),0) FROM signing_keys WHERE tenant_id=$1 AND coalesce(nullif(provider,''),'local_ed25519')='local_ed25519'`, request.TenantID).Scan(&version); err != nil {
			return empty, err
		}
		if version < 0 || version >= 2147483647 {
			return empty, app.ErrConflict
		}
		key, err := (localed25519.KeyFactory{}).GenerateSigningKey(ctx, request.TenantID, verificationdomain.SigningKeyDefaultProvider, int(version+1), request.CreatedAt)
		if err != nil {
			return empty, err
		}
		prepared = &key
		id, algorithm, public, from = key.Key.ID, key.Key.Algorithm, key.Key.PublicKey, key.Key.ValidFrom
		private = append([]byte(nil), key.PrivateMaterial...)
	} else if err != nil {
		return empty, fmt.Errorf("read Merkle signing key: %w", err)
	}
	success := false
	defer func() {
		if !success && prepared != nil {
			clear(prepared.PrivateMaterial)
		}
	}()
	if oversized || strings.TrimSpace(id) == "" || algorithm != "Ed25519" || len(private) != ed25519.PrivateKeySize || from.After(request.CreatedAt) || until != nil && !request.CreatedAt.Before(*until) || revoked != nil || compromised != nil {
		return empty, app.ErrConflict
	}
	publicBytes, err := base64.RawStdEncoding.Strict().DecodeString(public)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize || !ed25519.PublicKey(private[ed25519.SeedSize:]).Equal(ed25519.PublicKey(publicBytes)) {
		return empty, app.ErrConflict
	}
	derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	defer clear(derived)
	if !ed25519.PrivateKey(private).Equal(derived) {
		return empty, app.ErrConflict
	}
	value := ed25519.Sign(ed25519.PrivateKey(private), request.Payload)
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	success = true
	return verificationapp.SigningResult{Signature: verificationdomain.Signature{ID: application.NewID("sig"), TenantID: request.TenantID, SubjectType: request.SubjectType, SubjectID: request.SubjectID, KeyID: id, Algorithm: algorithm, Value: base64.RawStdEncoding.EncodeToString(value), CreatedAt: request.CreatedAt.UTC()}, NewKey: prepared}, nil
}
