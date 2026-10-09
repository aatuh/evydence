package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// ResolveReleaseBundleVerificationSubject locks only ownership coordinates.
// The tenant lock precedes bundle/signature/key locks and serializes lifecycle
// changes, including rotation where no signing-key row previously existed.
func (r verification) ResolveReleaseBundleVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return verificationapp.SubjectReference{}, err
	}
	subject := verificationapp.SubjectReference{TenantID: tenant, Type: "release_bundle", ID: id}
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT left(b.release_id,1025),left(r.product_id,1025),
		(octet_length(b.release_id)>1024 OR octet_length(r.product_id)>1024)
		FROM release_bundles b JOIN releases r ON r.id=b.release_id AND r.tenant_id=b.tenant_id
		JOIN products p ON p.id=r.product_id AND p.tenant_id=b.tenant_id
		WHERE b.tenant_id=$1 AND b.id=$2 FOR SHARE OF b,r,p`, tenant, id).Scan(&subject.Resources.ReleaseID, &subject.Resources.ProductID, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return verificationapp.SubjectReference{}, app.ErrNotFound
	}
	if err != nil {
		return verificationapp.SubjectReference{}, fmt.Errorf("lock verification bundle scope: %w", err)
	}
	if oversized || subject.Resources.ReleaseID == "" || subject.Resources.ProductID == "" {
		return verificationapp.SubjectReference{}, app.ErrConflict
	}
	return subject, nil
}

// ReadReleaseBundleVerification runs after authorization. JSON and strings
// are bounded in SQL before crossing the database boundary. Referenced rows
// are locked and only public signing material is selected, never ciphertext.
func (r verification) ReadReleaseBundleVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.ReleaseBundleVerificationSnapshot, error) {
	snapshot := verificationapp.ReleaseBundleVerificationSnapshot{Subject: subject}
	if subject.Type != "release_bundle" || subject.Resources != (application.ResourceReferences{ProductID: subject.Resources.ProductID, ReleaseID: subject.Resources.ReleaseID}) {
		return snapshot, app.ErrValidation
	}
	var manifest, refs []byte
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT
		CASE WHEN octet_length(manifest::text)<=$3 THEN manifest ELSE NULL END,
		left(manifest_hash,1025),
		CASE WHEN octet_length(signature_refs::text)<=$3 THEN signature_refs ELSE NULL END,
		octet_length(manifest_hash)>1024
		FROM release_bundles WHERE tenant_id=$1 AND id=$2 AND release_id=$4 FOR SHARE`, subject.TenantID, subject.ID, verificationapp.MaxBundleVerificationBytes, subject.Resources.ReleaseID).Scan(&manifest, &snapshot.ManifestHash, &refs, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, app.ErrNotFound
	}
	if err != nil {
		return snapshot, fmt.Errorf("read verification bundle: %w", err)
	}
	bytes := len(manifest) + len(refs) + len(snapshot.ManifestHash)
	if oversized || len(manifest) == 0 || len(refs) == 0 || bytes > verificationapp.MaxBundleVerificationBytes {
		return snapshot, app.ErrConflict
	}
	if err := json.Unmarshal(manifest, &snapshot.Manifest); err != nil || snapshot.Manifest == nil {
		return snapshot, app.ErrConflict
	}
	if err := json.Unmarshal(refs, &snapshot.SignatureRefs); err != nil || snapshot.SignatureRefs == nil || len(snapshot.SignatureRefs) > verificationapp.MaxBundleVerificationSignatures {
		return snapshot, app.ErrConflict
	}
	material, err := r.readVerificationSigningMaterial(ctx, subject, snapshot.SignatureRefs, bytes)
	snapshot.Signatures, snapshot.Keys = material.Signatures, material.Keys
	return snapshot, err
}

// readVerificationSigningMaterial is shared by signed bundle and Merkle
// projections. The caller's selected bytes count towards the same budget.
func (r verification) readVerificationSigningMaterial(ctx context.Context, subject verificationapp.SubjectReference, refs []string, bytes int) (verificationapp.ReleaseBundleVerificationSnapshot, error) {
	return r.readVerificationSigningMaterialWithLocks(ctx, subject, refs, bytes, true)
}

func (r verification) readVerificationSigningMaterialWithLocks(ctx context.Context, subject verificationapp.SubjectReference, refs []string, bytes int, lock bool) (verificationapp.ReleaseBundleVerificationSnapshot, error) {
	snapshot := verificationapp.ReleaseBundleVerificationSnapshot{Subject: subject, SignatureRefs: refs}
	if len(refs) > verificationapp.MaxBundleVerificationSignatures || bytes > verificationapp.MaxBundleVerificationBytes {
		return snapshot, app.ErrConflict
	}
	seen := make(map[string]bool, len(snapshot.SignatureRefs))
	for _, id := range snapshot.SignatureRefs {
		if id == "" || len(id) > 1024 || seen[id] {
			return snapshot, app.ErrConflict
		}
		seen[id] = true
	}
	if len(snapshot.SignatureRefs) == 0 {
		return snapshot, nil
	}
	var oversized bool
	rowLock := ""
	if lock {
		rowLock = " FOR SHARE"
	}
	rows, err := r.tx.Query(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(subject_type,65),left(subject_id,1025),left(key_id,1025),left(algorithm,65),left(value,16385),created_at,
		(octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(subject_type)>64 OR octet_length(subject_id)>1024 OR octet_length(key_id)>1024 OR octet_length(algorithm)>64 OR octet_length(value)>16384)
		FROM signatures WHERE tenant_id=$1 AND id=ANY($2) ORDER BY id LIMIT $3`+rowLock, subject.TenantID, snapshot.SignatureRefs, verificationapp.MaxBundleVerificationSignatures+1)
	if err != nil {
		return snapshot, fmt.Errorf("read bundle signatures: %w", err)
	}
	keys := map[string]bool{}
	for rows.Next() {
		var signature verificationdomain.Signature
		if err := rows.Scan(&signature.ID, &signature.TenantID, &signature.SubjectType, &signature.SubjectID, &signature.KeyID, &signature.Algorithm, &signature.Value, &signature.CreatedAt, &oversized); err != nil {
			rows.Close()
			return snapshot, err
		}
		bytes += len(signature.ID) + len(signature.TenantID) + len(signature.SubjectType) + len(signature.SubjectID) + len(signature.KeyID) + len(signature.Algorithm) + len(signature.Value)
		if oversized || bytes > verificationapp.MaxBundleVerificationBytes || len(snapshot.Signatures) == verificationapp.MaxBundleVerificationSignatures {
			rows.Close()
			return snapshot, app.ErrConflict
		}
		snapshot.Signatures = append(snapshot.Signatures, signature)
		keys[signature.KeyID] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return snapshot, fmt.Errorf("iterate bundle signatures: %w", err)
	}
	if len(keys) == 0 {
		return snapshot, nil
	}
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows, err = r.tx.Query(ctx, `SELECT left(id,1025),left(tenant_id,1025),left(algorithm,65),left(public_key,16385),left(status,65),created_at,valid_from,valid_until,revoked_at,left(revocation_semantics,65),left(historical_validity_policy,65),compromised_at,
		(octet_length(id)>1024 OR octet_length(tenant_id)>1024 OR octet_length(algorithm)>64 OR octet_length(public_key)>16384 OR octet_length(status)>64 OR octet_length(revocation_semantics)>64 OR octet_length(historical_validity_policy)>64)
		FROM signing_keys WHERE tenant_id=$1 AND id=ANY($2) ORDER BY id LIMIT $3`+rowLock, subject.TenantID, ids, verificationapp.MaxBundleVerificationSignatures+1)
	if err != nil {
		return snapshot, fmt.Errorf("read bundle public keys: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key verificationdomain.SigningKey
		var status string
		if err := rows.Scan(&key.ID, &key.TenantID, &key.Algorithm, &key.PublicKey, &status, &key.CreatedAt, &key.ValidFrom, &key.ValidUntil, &key.RevokedAt, &key.RevocationSemantics, &key.HistoricalValidityPolicy, &key.CompromisedAt, &oversized); err != nil {
			return snapshot, err
		}
		bytes += len(key.ID) + len(key.TenantID) + len(key.Algorithm) + len(key.PublicKey) + len(status) + len(key.RevocationSemantics) + len(key.HistoricalValidityPolicy)
		if status == "" {
			status = verificationdomain.SigningKeyStatusLegacyUnspecifiedValue
		}
		key.Status, err = verificationdomain.ParseSigningKeyStatus(status)
		if err != nil || oversized || bytes > verificationapp.MaxBundleVerificationBytes || len(snapshot.Keys) == verificationapp.MaxBundleVerificationSignatures {
			return snapshot, app.ErrConflict
		}
		snapshot.Keys = append(snapshot.Keys, key)
	}
	if err := rows.Err(); err != nil {
		return snapshot, fmt.Errorf("iterate bundle public keys: %w", err)
	}
	return snapshot, nil
}
