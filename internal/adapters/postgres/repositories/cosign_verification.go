package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func (r verification) cosignCoordinates(ctx context.Context, tenant, id string, lock bool) (string, string, error) {
	query := `SELECT left(artifact_id,1025),left(subject_digest,1025),octet_length(artifact_id)>1024 OR octet_length(subject_digest)>1024 FROM artifact_signatures WHERE tenant_id=$1 AND id=$2`
	if lock {
		query += ` FOR SHARE`
	}
	var artifact, digest string
	var large bool
	err := r.tx.QueryRow(ctx, query, tenant, id).Scan(&artifact, &digest, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", app.ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("read Cosign coordinates: %w", err)
	}
	if large || artifact == "" || digest == "" {
		return "", "", app.ErrConflict
	}
	return artifact, digest, nil
}
func (r verification) ResolveCosignSubject(ctx context.Context, tenant, id string) (verificationapp.CosignSubject, error) {
	subject := verificationapp.CosignSubject{TenantID: tenant, ArtifactSignatureID: id}
	artifact, digest, err := r.cosignCoordinates(ctx, tenant, id, false)
	if err != nil {
		return subject, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return subject, err
	}
	// Match artifact publication's parent-before-signature lock ordering.
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM artifacts WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, artifact); err != nil {
		return subject, err
	}
	lockedArtifact, lockedDigest, err := r.cosignCoordinates(ctx, tenant, id, true)
	if err != nil {
		return subject, err
	}
	if lockedArtifact != artifact || lockedDigest != digest {
		return subject, app.ErrConflict
	}
	subject.ArtifactID, subject.SubjectDigest = artifact, digest
	subject.Resources = application.ResourceReferences{ArtifactID: artifact}
	// The image is optional metadata. Select one deterministically without
	// loading/scanning all images into the process; only the chosen row locks.
	var image string
	var large bool
	err = r.tx.QueryRow(ctx, `SELECT left(id,1025),octet_length(id)>1024 FROM container_images WHERE tenant_id=$1 AND artifact_id=$2 AND digest=$3 ORDER BY id LIMIT 1 FOR SHARE`, tenant, artifact, digest).Scan(&image, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return subject, nil
	}
	if err != nil {
		return subject, fmt.Errorf("read Cosign image coordinate: %w", err)
	}
	if large {
		return subject, app.ErrConflict
	}
	subject.ContainerImageID = image
	return subject, nil
}
func (r verification) ReadCosignSnapshot(ctx context.Context, subject verificationapp.CosignSubject) (verificationapp.CosignSnapshot, error) {
	snapshot := verificationapp.CosignSnapshot{Subject: subject}
	var artifact, digest string
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(artifact_id,1025),left(subject_digest,1025),left(algorithm,65),left(coalesce(payload_ref,''),4097),left(coalesce(payload_hash,''),1025),
 octet_length(artifact_id)>1024 OR octet_length(subject_digest)>1024 OR octet_length(algorithm)>64 OR coalesce(octet_length(payload_ref)>4096,false) OR coalesce(octet_length(payload_hash)>1024,false)
 FROM artifact_signatures WHERE tenant_id=$1 AND id=$2 FOR SHARE`, subject.TenantID, subject.ArtifactSignatureID).Scan(&artifact, &digest, &snapshot.Algorithm, &snapshot.PayloadRef, &snapshot.PayloadHash, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, app.ErrNotFound
	}
	if err != nil {
		return snapshot, fmt.Errorf("read Cosign signature: %w", err)
	}
	if large || artifact != subject.ArtifactID || digest != subject.SubjectDigest {
		return snapshot, app.ErrConflict
	}
	err = r.tx.QueryRow(ctx, `SELECT left(digest,1025),octet_length(digest)>1024 FROM artifacts WHERE tenant_id=$1 AND id=$2 FOR SHARE`, subject.TenantID, subject.ArtifactID).Scan(&snapshot.ArtifactDigest, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, app.ErrNotFound
	}
	if err != nil {
		return snapshot, err
	}
	if large {
		return snapshot, app.ErrConflict
	}
	if snapshot.PayloadHash == "" {
		return snapshot, nil
	}
	var final, status string
	err = r.tx.QueryRow(ctx, `SELECT left(final_key,4097),left(media_type,4097),size,left(status,65),octet_length(final_key)>4096 OR octet_length(media_type)>4096 OR octet_length(status)>64
 FROM object_payloads WHERE tenant_id=$1 AND digest=$2 FOR SHARE`, subject.TenantID, snapshot.PayloadHash).Scan(&final, &snapshot.PayloadMediaType, &snapshot.PayloadSize, &status, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, fmt.Errorf("read Cosign payload lifecycle: %w", err)
	}
	if large || snapshot.PayloadSize < 0 || snapshot.PayloadSize > verificationapp.MaxCosignPayloadBytes {
		return snapshot, app.ErrConflict
	}
	_, canonical, keyErr := app.CanonicalObjectPayloadKeys(subject.TenantID, snapshot.PayloadHash)
	snapshot.PayloadFinalized = keyErr == nil && status == string(app.ObjectPayloadFinalized) && final == canonical && snapshot.PayloadRef == "object://"+final
	return snapshot, nil
}
